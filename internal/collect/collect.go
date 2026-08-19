package collect

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/automationpi/govlens/internal/store"
)

// Collector holds the SP tokens and per-run caches.
type Collector struct {
	sp    *SP
	arm   string
	graph string

	pseudonymize bool
	roleCache    map[string]string
	principalIDs map[string]struct{}
}

// Options controls one collection run.
type Options struct {
	TenantLabel  string // override tenant key; default is the SP's Entra tenant id
	Display      string // override display name; default is the Entra org name
	CollectedAt  time.Time
	MGID         string // if set, only subscriptions under this MG are collected
	Pseudonymize bool   // hash principal names instead of resolving them via Graph
}

// New authenticates the SP for both ARM and Graph up front.
func New(ctx context.Context, sp *SP) (*Collector, error) {
	arm, err := sp.Token(ctx, armScope)
	if err != nil {
		return nil, err
	}
	graph, err := sp.Token(ctx, graphScope)
	if err != nil {
		return nil, err
	}
	return &Collector{
		sp: sp, arm: arm, graph: graph,
		roleCache:    map[string]string{},
		principalIDs: map[string]struct{}{},
	}, nil
}

// Collect gathers RBAC + policy compliance and Conditional Access and assembles
// a store.RunData ready to load.
func (c *Collector) Collect(ctx context.Context, opts Options) (store.RunData, error) {
	c.pseudonymize = opts.Pseudonymize

	// Identity: key by the Entra tenant id; display defaults to the org name.
	tenant := opts.TenantLabel
	if tenant == "" {
		tenant = c.sp.TenantID
	}
	display := opts.Display
	if display == "" {
		display = c.organizationName(ctx)
	}
	if display == "" {
		display = tenant
	}
	rd := store.RunData{Tenant: tenant, TenantDisplay: display, CollectedAt: opts.CollectedAt, Label: "lean-collector"}
	log.Printf("tenant: %s (%s)", display, tenant)

	var subs []subscription
	var err error
	if opts.MGID != "" {
		subs, err = c.subscriptionsUnderMG(ctx, opts.MGID)
	} else {
		subs, err = c.subscriptions(ctx)
	}
	if err != nil {
		return rd, err
	}
	log.Printf("subscriptions in scope: %d", len(subs))
	for _, sub := range subs {
		rd.Subscriptions = append(rd.Subscriptions, store.Subscription{ID: sub.ID, Name: sub.DisplayName})
	}

	// --- Azure: RBAC + policy compliance across all subs ---
	var cc complianceCounts
	rbacSeen := false
	catalog := map[string]store.CatalogRole{} // deduped by roleDefinitionId across subs
	for _, s := range subs {
		ra, err := c.roleAssignments(ctx, s)
		if err != nil {
			log.Printf("  rbac %s: %v", s.DisplayName, err)
		} else {
			rd.Assignments = append(rd.Assignments, ra...)
			rbacSeen = true
		}
		if defs, err := c.roleDefinitions(ctx, s); err != nil {
			log.Printf("  roledefs %s: %v", s.DisplayName, err)
		} else {
			for _, d := range defs {
				catalog[d.RoleDefID] = d
			}
		}
		if rgs, err := c.resourceGroups(ctx, s); err != nil {
			log.Printf("  resourcegroups %s: %v", s.DisplayName, err)
		} else {
			for _, name := range rgs {
				rd.ResourceGroups = append(rd.ResourceGroups, store.ResourceGroup{SubID: s.ID, Name: name})
			}
		}
		pf, pcc, err := c.policyCompliance(ctx, s)
		if err != nil {
			log.Printf("  policy %s: %v", s.DisplayName, err)
		} else {
			rd.Findings = append(rd.Findings, pf...)
			cc.compliant += pcc.compliant
			cc.nonCompliant += pcc.nonCompliant
			cc.total += pcc.total
			cc.nonCompliantAssignments += pcc.nonCompliantAssignments
		}
	}
	if rbacSeen {
		rd.Sources = append(rd.Sources, store.SrcRBAC)
		// Count unique assignment ids: an MG-scoped/inherited assignment appears
		// in every subscription's roleAssignments list, so raw rows over-count.
		rd.Metrics = append(rd.Metrics, store.Metric{Domain: "azure", Category: "rbac", Key: "count",
			Value: float64(countUniqueKind(rd.Assignments, "rbac"))})
	}
	if cc.total > 0 {
		rd.Sources = append(rd.Sources, store.SrcPolicy)
		rd.Metrics = append(rd.Metrics,
			store.Metric{Domain: "azure", Category: "policy_compliance", Key: "compliant_resources", Value: float64(cc.compliant)},
			store.Metric{Domain: "azure", Category: "policy_compliance", Key: "noncompliant_resources", Value: float64(cc.nonCompliant)},
			store.Metric{Domain: "azure", Category: "policy_compliance", Key: "noncompliant_assignments", Value: float64(cc.nonCompliantAssignments)},
			store.Metric{Domain: "azure", Category: "policy_compliance", Key: "total_assignments", Value: float64(cc.total)},
		)
	}

	// --- Entra: Conditional Access ---
	ca, cac, err := c.conditionalAccess(ctx)
	if err != nil {
		log.Printf("  conditional access: %v", err)
	} else {
		rd.Assignments = append(rd.Assignments, ca...)
		rd.Sources = append(rd.Sources, store.SrcCA)
		rd.Metrics = append(rd.Metrics,
			store.Metric{Domain: "entra", Category: "ca_policy", Key: "total", Value: float64(cac.total)},
			store.Metric{Domain: "entra", Category: "ca_policy", Key: "enabled", Value: float64(cac.enabled)},
			store.Metric{Domain: "entra", Category: "ca_policy", Key: "report_only", Value: float64(cac.reportOnly)},
			store.Metric{Domain: "entra", Category: "ca_policy", Key: "disabled", Value: float64(cac.disabled)},
		)
	}

	// --- Entra: directory role assignments (privileged access review) ---
	dirRoles, err := c.directoryRoles(ctx)
	if err != nil {
		log.Printf("  directory roles: %v", err)
	} else {
		rd.Assignments = append(rd.Assignments, dirRoles...)
		rd.Sources = append(rd.Sources, store.SrcEntraRoles)
	}

	// Resolve RBAC + directory-role principal names/types in one Graph batch.
	c.resolvePrincipals(ctx, rd.Assignments)

	// Dormancy (roadmap #2): last sign-in per principal. Degrades to nil without the
	// AuditLog.Read.All permission, so this never blocks a collection.
	if rd.Activity = c.signInActivity(ctx); len(rd.Activity) > 0 {
		log.Printf("sign-in activity: captured for %d principal(s)", len(rd.Activity))
	}

	// Directory-role metrics + compliance findings (need resolved principal types).
	if len(dirRoles) > 0 {
		m, f := directoryRoleReview(rd.Assignments)
		rd.Metrics = append(rd.Metrics, m...)
		rd.Findings = append(rd.Findings, f...)
	}

	// Materialize the deduped role catalog for the self-service grant module.
	if len(catalog) > 0 {
		low, med, priv := 0, 0, 0
		for _, cr := range catalog {
			rd.Catalog = append(rd.Catalog, cr)
			switch cr.Tier {
			case "low":
				low++
			case "medium":
				med++
			default:
				priv++
			}
		}
		log.Printf("role catalog: %d roles (low=%d medium=%d privileged=%d)", len(rd.Catalog), low, med, priv)
	}

	log.Printf("collected: %d assignments, %d findings, %d resource groups, sources=%v",
		len(rd.Assignments), len(rd.Findings), len(rd.ResourceGroups), rd.Sources)
	return rd, nil
}

// privilegedDirRoles are the high-impact Entra admin roles a privileged-access
// review cares about most.
var privilegedDirRoles = map[string]bool{
	"Global Administrator": true, "Privileged Role Administrator": true,
	"Privileged Authentication Administrator": true, "Security Administrator": true,
	"Conditional Access Administrator": true, "Application Administrator": true,
	"Cloud Application Administrator": true, "User Administrator": true,
	"Authentication Administrator": true, "Exchange Administrator": true,
	"SharePoint Administrator": true, "Hybrid Identity Administrator": true,
	"Intune Administrator": true, "Domain Name Administrator": true,
}

// directoryRoleReview derives review metrics and compliance findings from the
// collected Entra directory role assignments.
func directoryRoleReview(assigns []store.Assignment) ([]store.Metric, []store.Finding) {
	total, priv, ga := 0, 0, 0
	var findings []store.Finding
	for _, a := range assigns {
		if a.Kind != "entra_role" {
			continue
		}
		total++
		isPriv := privilegedDirRoles[a.Role]
		if isPriv {
			priv++
		}
		if a.Role == "Global Administrator" {
			ga++
		}
		// A service principal holding a privileged directory role is a red flag.
		if isPriv && a.PrincipalType == "ServicePrincipal" {
			findings = append(findings, store.Finding{
				Domain: "entra", Source: "entra-roles", ControlID: "priv-sp:" + a.Ident,
				Title:    "Service principal holds privileged role: " + a.Role + " — " + a.Principal,
				Severity: "High", Status: "non_compliant", Category: "Privileged Access", Scope: a.Scope,
			})
		}
	}
	metrics := []store.Metric{
		{Domain: "entra", Category: "entra_role", Key: "total", Value: float64(total)},
		{Domain: "entra", Category: "entra_role", Key: "privileged", Value: float64(priv)},
		{Domain: "entra", Category: "entra_role", Key: "global_admins", Value: float64(ga)},
	}
	// Global Administrator count: Microsoft recommends a small number (2–4) of
	// permanent Global Admins — too many widens blast radius, too few risks lockout.
	gaStatus, gaSev := "compliant", "Info"
	if ga > 5 {
		gaStatus, gaSev = "non_compliant", "High"
	} else if ga < 2 {
		gaStatus, gaSev = "non_compliant", "Low"
	}
	findings = append(findings, store.Finding{
		Domain: "entra", Source: "entra-roles", ControlID: "ga-count",
		Title:    fmt.Sprintf("Global Administrator count: %d (recommended 2–4)", ga),
		Severity: gaSev, Status: gaStatus, Category: "Privileged Access", Scope: "Directory",
	})
	return metrics, findings
}

// countUniqueKind counts distinct assignment identities of a kind (dedupes
// inherited assignments that repeat across subscriptions).
func countUniqueKind(as []store.Assignment, kind string) int {
	seen := map[string]struct{}{}
	for _, a := range as {
		if a.Kind == kind {
			seen[a.Ident] = struct{}{}
		}
	}
	return len(seen)
}

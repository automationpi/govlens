package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/automationpi/govlens/internal/store"
)

// conditionalAccess pulls Entra CA policies from Graph.
func (c *Collector) conditionalAccess(ctx context.Context) ([]store.Assignment, caCounts, error) {
	raw, err := pagedValues(ctx, c.graph, graphBase+"/identity/conditionalAccess/policies?$select=id,displayName,state,grantControls")
	if err != nil {
		return nil, caCounts{}, err
	}
	var out []store.Assignment
	var cc caCounts
	for _, r := range raw {
		var p struct {
			ID            string `json:"id"`
			DisplayName   string `json:"displayName"`
			State         string `json:"state"`
			GrantControls struct {
				BuiltInControls []string `json:"builtInControls"`
			} `json:"grantControls"`
		}
		_ = json.Unmarshal(r, &p)
		switch p.State {
		case "enabled":
			cc.enabled++
		case "enabledForReportingButNotEnforced":
			cc.reportOnly++
		default:
			cc.disabled++
		}
		cc.total++
		out = append(out, store.Assignment{
			Domain:  "entra",
			Kind:    "ca_policy",
			Ident:   p.ID,
			Role:    p.State,
			Display: p.DisplayName,
			Scope:   strings.Join(p.GrantControls.BuiltInControls, "+"),
		})
	}
	return out, cc, nil
}

type caCounts struct{ total, enabled, reportOnly, disabled int }

// directoryRoles collects Entra directory role assignments (Global Administrator,
// User Administrator, etc.) held by users, groups, and service principals — the
// basis for a privileged-access review. Role definition names are resolved once.
func (c *Collector) directoryRoles(ctx context.Context) ([]store.Assignment, error) {
	// role definition id -> display name
	defs := map[string]string{}
	rawDefs, err := pagedValues(ctx, c.graph, graphBase+"/roleManagement/directory/roleDefinitions?$select=id,displayName")
	if err != nil {
		return nil, err
	}
	for _, r := range rawDefs {
		var d struct{ ID, DisplayName string }
		_ = json.Unmarshal(r, &d)
		defs[d.ID] = d.DisplayName
	}

	rawAssign, err := pagedValues(ctx, c.graph, graphBase+"/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId")
	if err != nil {
		return nil, err
	}
	var out []store.Assignment
	for _, r := range rawAssign {
		var a struct {
			ID               string `json:"id"`
			PrincipalID      string `json:"principalId"`
			RoleDefinitionID string `json:"roleDefinitionId"`
			DirectoryScopeID string `json:"directoryScopeId"`
		}
		_ = json.Unmarshal(r, &a)
		role := defs[a.RoleDefinitionID]
		if role == "" {
			role = a.RoleDefinitionID
		}
		scope := a.DirectoryScopeID
		if scope == "" || scope == "/" {
			scope = "Directory (tenant-wide)"
		}
		out = append(out, store.Assignment{
			Domain:    "entra",
			Kind:      "entra_role",
			Ident:     a.ID,
			Principal: a.PrincipalID, // display + type resolved later
			Role:      role,
			Scope:     scope,
		})
		c.principalIDs[a.PrincipalID] = struct{}{}
	}
	return out, nil
}

// organizationName returns the tenant's Entra display name (e.g. "Example Org"),
// used as the human label. Empty on failure — the caller falls back to the id.
func (c *Collector) organizationName(ctx context.Context) string {
	var res struct {
		Value []struct {
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := getJSON(ctx, c.graph, graphBase+"/organization?$select=displayName", &res); err == nil && len(res.Value) > 0 {
		return res.Value[0].DisplayName
	}
	return ""
}

// pseudonym returns a stable, non-reversible label for a principal id, used when
// PII pseudonymization is on (so real names/UPNs never land in the store).
func pseudonym(principalID string) string {
	sum := sha256.Sum256([]byte(principalID))
	return "principal-" + hex.EncodeToString(sum[:])[:12]
}

// principalKinds are the assignment kinds whose Principal field starts as an id
// and needs Graph resolution (RBAC role assignments + Entra directory roles).
func isPrincipalKind(kind string) bool { return kind == "rbac" || kind == "entra_role" }

// odataType maps a Graph @odata.type to our short principal type label.
func odataType(t string) string {
	switch {
	case strings.Contains(t, "servicePrincipal"):
		return "ServicePrincipal"
	case strings.Contains(t, "group"):
		return "Group"
	case strings.Contains(t, "user"):
		return "User"
	default:
		return ""
	}
}

// resolvePrincipals turns collected principal ids into display names + types in
// one batched Graph getByIds call, rewriting RBAC and directory-role assignments
// in place. With pseudonymize set, it skips Graph and uses stable hashes.
func (c *Collector) resolvePrincipals(ctx context.Context, assigns []store.Assignment) {
	if c.pseudonymize {
		for i := range assigns {
			if isPrincipalKind(assigns[i].Kind) {
				assigns[i].Principal = pseudonym(assigns[i].Principal)
				assigns[i].Display = assigns[i].Principal + " — " + assigns[i].Role
			}
		}
		return
	}
	ids := make([]string, 0, len(c.principalIDs))
	for id := range c.principalIDs {
		if id != "" {
			ids = append(ids, id)
		}
	}
	names := map[string]string{}
	types := map[string]string{}
	for i := 0; i < len(ids); i += 900 { // getByIds cap is 1000
		end := i + 900
		if end > len(ids) {
			end = len(ids)
		}
		var res struct {
			Value []struct {
				ID          string `json:"id"`
				OType       string `json:"@odata.type"`
				DisplayName string `json:"displayName"`
				UPN         string `json:"userPrincipalName"`
			} `json:"value"`
		}
		body := map[string]any{"ids": ids[i:end]}
		if err := postJSON(ctx, c.graph, graphBase+"/directoryObjects/getByIds", body, &res); err != nil {
			continue // best-effort; leave unresolved as the id
		}
		for _, o := range res.Value {
			n := o.DisplayName
			if n == "" {
				n = o.UPN
			}
			names[o.ID] = n
			types[o.ID] = odataType(o.OType)
		}
	}
	for i := range assigns {
		if !isPrincipalKind(assigns[i].Kind) {
			continue
		}
		origID := assigns[i].Principal // still the principal id at this point
		if n, ok := names[origID]; ok && n != "" {
			assigns[i].Principal = n
		}
		if assigns[i].PrincipalType == "" { // directory roles don't carry a type; fill it in
			assigns[i].PrincipalType = types[origID]
		}
		assigns[i].Display = assigns[i].Principal + " — " + assigns[i].Role
	}
}

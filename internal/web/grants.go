package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/auth"
	"github.com/automationpi/govlens/internal/store"
)

func (s *Server) grantRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/request", s.requestPage)
	mux.HandleFunc("/request/submit", s.requestSubmit)
	mux.HandleFunc("/grant/decide", s.grantDecide)
	mux.HandleFunc("/grant/decide-bulk", s.grantDecideBulk)
}

type scopeOption struct {
	SubID string
	Scope string // full ARM scope, e.g. /subscriptions/<id>
	Name  string
}

// levelView is one access "level" (a tier, in user-facing terms) offered on the
// request form, carrying its roles and the policy that governs it.
type levelView struct {
	Key              string // low | medium | privileged
	Label            string // Read-only | Contribute | Admin
	Blurb            string
	Roles            []store.RequestableRole
	DefaultRoleDefID string
	DefaultRoleName  string
	MaxDays          int
	DefaultDays      int
	ApproverTier     string
	AllowPermanent   bool
}

type requestPageData struct {
	Tenant        string
	TenantDisplay string
	Tenants       []store.TenantInfo
	Levels        []levelView
	Scopes        []scopeOption
	RGsJSON       template.JS // {subId: ["rg-a","rg-b"], ...} for the resource-group picker
	User          *auth.User
	Notice        string
	ModuleLive    bool
	HasOid        bool
}

// levelMeta maps a policy tier to its user-facing label + blurb, in display order.
var levelMeta = []struct{ Key, Label, Blurb string }{
	{"low", "Read-only", "View resources and settings. No changes."},
	{"medium", "Contribute", "Create and manage resources. Cannot manage others' access."},
	{"privileged", "Admin", "Full control, including managing access. Requires elevated approval."},
}

// requestPage renders the self-service access-request form. Any signed-in user
// may request; intake is open only when the module is live.
func (s *Server) requestPage(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	tenants, _ := s.store.Tenants(ctx)
	tenant := s.resolveTenant(r, tenants)
	d := requestPageData{Tenant: tenant, TenantDisplay: displayFor(tenants, tenant), Tenants: tenants,
		User: u, Notice: r.URL.Query().Get("err"), HasOid: u.Oid != ""}
	d.ModuleLive = s.store.GrantReadinessAt(ctx, tenant, time.Now()).Live
	d.Scopes = s.optedInScopes(ctx, tenant)
	d.Levels = s.buildLevels(ctx, tenant)

	// Resource groups per opted-in subscription, as a JSON map for the picker.
	rgAll, _ := s.store.ResourceGroupsBySub(ctx, tenant)
	rgs := map[string][]string{}
	for _, sc := range d.Scopes {
		if list := rgAll[sc.SubID]; len(list) > 0 {
			rgs[sc.SubID] = list
		}
	}
	if b, err := json.Marshal(rgs); err == nil {
		d.RGsJSON = template.JS(b)
	} else {
		d.RGsJSON = template.JS("{}")
	}
	s.render(w, "request.html", d)
}

// buildLevels groups the requestable catalog by tier into user-facing levels,
// attaching each tier's policy. Only levels with at least one role are returned.
func (s *Server) buildLevels(ctx context.Context, tenant string) []levelView {
	roles, _ := s.store.RequestableRoles(ctx, tenant)
	byTier := map[string][]store.RequestableRole{}
	for _, r := range roles {
		byTier[r.Tier] = append(byTier[r.Tier], r)
	}
	pol := map[string]store.TierPolicy{}
	if pols, _ := s.store.TierPolicies(ctx, tenant); pols != nil {
		for _, p := range pols {
			pol[p.Tier] = p
		}
	}
	var out []levelView
	for _, m := range levelMeta {
		rs := byTier[m.Key]
		if len(rs) == 0 {
			continue
		}
		p := pol[m.Key]
		lv := levelView{Key: m.Key, Label: m.Label, Blurb: m.Blurb, Roles: rs,
			MaxDays: p.MaxDays, DefaultDays: p.DefaultDays, ApproverTier: p.ApproverTier,
			AllowPermanent: p.AllowPermanent}
		// Sensible default: "Reader" for read-only, else the first role.
		lv.DefaultRoleDefID, lv.DefaultRoleName = rs[0].RoleDefID, rs[0].RoleName
		for _, r := range rs {
			if r.RoleName == "Reader" {
				lv.DefaultRoleDefID, lv.DefaultRoleName = r.RoleDefID, r.RoleName
				break
			}
		}
		out = append(out, lv)
	}
	return out
}

// optedInScopes returns the subscriptions opted into the grant module, as ARM scopes.
func (s *Server) optedInScopes(ctx context.Context, tenant string) []scopeOption {
	optins, _ := s.store.ScopeOptIns(ctx, tenant, store.ModuleGrant)
	if len(optins) == 0 {
		return nil
	}
	on := map[string]bool{}
	for _, sc := range optins {
		on[sc] = true
	}
	subs, _ := s.store.Subscriptions(ctx, tenant)
	var out []scopeOption
	for _, sub := range subs {
		if on[sub.ID] {
			out = append(out, scopeOption{SubID: sub.ID, Scope: "/subscriptions/" + sub.ID, Name: sub.Name})
		}
	}
	return out
}

func (s *Server) requestSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u := userOf(r)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	_ = r.ParseForm()
	tenant := r.FormValue("tenant")
	roleDefID := r.FormValue("role_def_id")
	subID := strings.TrimSpace(r.FormValue("sub"))
	rg := strings.TrimSpace(r.FormValue("rg"))
	days := atoiSafe(r.FormValue("days"))
	permanent := r.FormValue("permanent") == "on"
	reason := r.FormValue("reason")
	fail := func(msg string) { http.Redirect(w, r, "/request?err="+url.QueryEscape(msg), http.StatusSeeOther) }

	if u.Oid == "" {
		fail("Your directory object id isn't in this session — sign out and back in, then retry.")
		return
	}
	if len(strings.TrimSpace(reason)) < 10 {
		fail("Please give a short justification (what you're working on and why you need this).")
		return
	}
	if !s.store.IsGrantable(ctx, tenant, roleDefID) {
		fail("That role isn't available for self-service.")
		return
	}
	// Build the ARM scope: subscription, optionally narrowed to a resource group.
	scope := "/subscriptions/" + subID
	if !s.scopeOptedIn(ctx, tenant, scope) {
		fail("That subscription isn't open for self-service requests.")
		return
	}
	if rg != "" {
		if !s.store.ResourceGroupExists(ctx, tenant, subID, rg) {
			fail("That resource group isn't known for the selected subscription.")
			return
		}
		scope += "/resourceGroups/" + rg
	}
	// Unlimited is only proposable where the role's tier policy allows it.
	if permanent && !s.tierPolicyFor(ctx, tenant, roleDefID).AllowPermanent {
		fail("Unlimited access isn't allowed for that level — choose a duration.")
		return
	}
	if permanent {
		days = 0
	}
	name, _ := s.store.RoleCatalogName(ctx, tenant, roleDefID)
	_, err := s.store.CreateGrantRequest(ctx, store.NewGrantRequest{
		Tenant: tenant, RoleDefID: roleDefID, RoleName: name, Scope: scope,
		PrincipalOid: u.Oid, PrincipalName: nameOrEmail(u), RequestedBy: u.Email,
		Reason: reason, RequestedDays: days, RequestedPermanent: permanent,
	})
	if err != nil {
		fail("Could not open the request: " + err.Error())
		return
	}
	http.Redirect(w, r, "/requests?tenant="+url.QueryEscape(tenant), http.StatusSeeOther)
}

func (s *Server) scopeOptedIn(ctx context.Context, tenant, scope string) bool {
	sub := store.SubscriptionOfScope(scope)
	for _, o := range s.optedInScopes(ctx, tenant) {
		if o.Scope == scope || store.SubscriptionOfScope(o.Scope) == sub {
			return true
		}
	}
	return false
}

// grantDecide approves or rejects a pending grant, setting the expiry on approval.
func (s *Server) grantDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u := userOf(r)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	tenant := r.FormValue("tenant")
	approve := r.FormValue("decision") == "approve"
	note := r.FormValue("note")
	days := atoiSafe(r.FormValue("days"))
	permanent := r.FormValue("permanent") == "on"

	outcome, reason := s.applyGrantDecision(ctx, u, id, approve, note, days, permanent)
	dest := "/requests?tenant=" + url.QueryEscape(tenant)
	if outcome == "skipped" {
		dest += "&err=" + url.QueryEscape(reason)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// grantDecideBulk applies one decision (approve/reject) with a single note and a
// single expiry to every selected grant request. Each request is authorized and
// expiry-clamped against its own tier, so a batch may safely span tiers; any that
// can't be applied (wrong scope, permanent-not-allowed) are skipped and summarized.
func (s *Server) grantDecideBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u := userOf(r)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	_ = r.ParseForm()
	tenant := r.FormValue("tenant")
	approve := r.FormValue("decision") == "approve"
	note := r.FormValue("note")
	days := atoiSafe(r.FormValue("days"))
	permanent := r.FormValue("permanent") == "on"

	var approved, rejected int
	skips := map[string]int{}
	for _, sid := range r.Form["sel"] {
		id, err := strconv.ParseInt(sid, 10, 64)
		if err != nil {
			continue
		}
		switch outcome, reason := s.applyGrantDecision(ctx, u, id, approve, note, days, permanent); outcome {
		case "approved":
			approved++
		case "rejected":
			rejected++
		default:
			skips[reason]++
		}
	}
	http.Redirect(w, r, "/requests?tenant="+url.QueryEscape(tenant)+"&err="+url.QueryEscape(bulkSummary(approved, rejected, skips)), http.StatusSeeOther)
}

// applyGrantDecision authorizes and applies a single grant decision, clamping the
// expiry to the request's tier. It writes nothing to the response — it returns a
// one-word outcome ("approved"/"rejected"/"skipped") and, when skipped, a reason.
func (s *Server) applyGrantDecision(ctx context.Context, u *auth.User, id int64, approve bool, note string, days int, permanent bool) (outcome, reason string) {
	req, err := s.store.GetAccessRequest(ctx, id)
	if err != nil || req.Action != "grant" {
		return "skipped", "not found"
	}
	tp := s.tierPolicyFor(ctx, req.Tenant, req.RoleDefID)

	// Authorization: a 'global' approver tier requires a global approver; otherwise
	// the scope's approver may decide.
	if tp.ApproverTier == "global" {
		if !u.IsApprover() {
			return "skipped", "needs global approver"
		}
	} else if !u.CanApprove(req.Scope) {
		return "skipped", "not your scope"
	}

	if !approve {
		if err := s.store.DecideGrantRequest(ctx, id, false, u.Email, note, nil); err != nil {
			return "skipped", err.Error()
		}
		return "rejected", ""
	}

	// Approve — compute expiry from the approver's choice within tier bounds.
	var expiresAt *time.Time
	if permanent {
		if !tp.AllowPermanent {
			return "skipped", "permanent not allowed for tier"
		}
	} else {
		d := days
		if d <= 0 {
			d = tp.DefaultDays
		}
		if d <= 0 {
			d = 30
		}
		if tp.MaxDays > 0 && d > tp.MaxDays {
			d = tp.MaxDays
		}
		t := time.Now().Add(time.Duration(d) * 24 * time.Hour)
		expiresAt = &t
	}
	if err := s.store.DecideGrantRequest(ctx, id, true, u.Email, note, expiresAt); err != nil {
		return "skipped", err.Error()
	}
	return "approved", ""
}

// bulkSummary renders a short one-line result for a bulk decision, shown in the
// requests-page notice banner (e.g. "approved 7, skipped 2 (not your scope)").
func bulkSummary(approved, rejected int, skips map[string]int) string {
	var parts []string
	if approved > 0 {
		parts = append(parts, fmt.Sprintf("approved %d", approved))
	}
	if rejected > 0 {
		parts = append(parts, fmt.Sprintf("rejected %d", rejected))
	}
	for reason, n := range skips {
		parts = append(parts, fmt.Sprintf("skipped %d (%s)", n, reason))
	}
	if len(parts) == 0 {
		return "No requests were selected."
	}
	return strings.Join(parts, ", ") + "."
}

// tierPolicyFor resolves the tier policy governing a role (empty-ish default if unknown).
func (s *Server) tierPolicyFor(ctx context.Context, tenant, roleDefID string) store.TierPolicy {
	_, tier := s.store.RoleCatalogName(ctx, tenant, roleDefID)
	pols, _ := s.store.TierPolicies(ctx, tenant)
	for _, p := range pols {
		if p.Tier == tier {
			return p
		}
	}
	// Unknown tier → treat as privileged/global, no permanent (fail-closed).
	return store.TierPolicy{Tier: "privileged", ApproverTier: "global", DefaultDays: 7, MaxDays: 7}
}

func nameOrEmail(u *auth.User) string {
	if n := strings.TrimSpace(u.Name); n != "" {
		return n
	}
	return u.Email
}

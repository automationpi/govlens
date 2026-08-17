package web

import (
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/auth"
	"github.com/automationpi/govlens/internal/collect"
	"github.com/automationpi/govlens/internal/store"
)

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin", s.adminPage)
	mux.HandleFunc("/admin/grant", s.adminGrant)
	mux.HandleFunc("/admin/revoke", s.adminRevoke)
	mux.HandleFunc("/admin/protect", s.adminProtect)
	mux.HandleFunc("/admin/unprotect", s.adminUnprotect)
	mux.HandleFunc("/admin/typepolicy", s.adminTypePolicy)
	mux.HandleFunc("/admin/module", s.adminModule)
	mux.HandleFunc("/admin/grantsp", s.adminGrantSP)
	mux.HandleFunc("/admin/grantsp/probe", s.adminGrantSPProbe)
	mux.HandleFunc("/admin/tierpolicy", s.adminTierPolicy)
	mux.HandleFunc("/admin/scopeoptin", s.adminScopeOptIn)
}

type adminData struct {
	User          *auth.User
	Tenant        string
	Users         []store.AppUser
	Protected     []store.ProtectedRole
	Subscriptions []store.Subscription
	TypePolicies  map[string]string // principal type -> "" | blocked | global
	Enabled       bool
	Notice        string // transient banner (e.g. why "go live" was refused)

	// Self-service grant module.
	Grant      store.GrantReadiness
	GrantSP    store.GrantSPConfig
	TierPolicy []store.TierPolicy
	OptIns     map[string]bool // subscription id -> opted in
}

// adminTenant resolves the tenant this admin session operates on (single-tenant
// today: the first known tenant). Returns "" if none collected yet.
func (s *Server) adminTenant(r *http.Request) string {
	if tenants, _ := s.store.Tenants(r.Context()); len(tenants) > 0 {
		return tenants[0].ID
	}
	return ""
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "anyadmin") // global OR subscription-scoped admin
	if !ok {
		return
	}
	ctx := r.Context()
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	prot, _ := s.store.ProtectedRoles(ctx)
	tenant := s.adminTenant(r)
	var subs []store.Subscription
	if tenant != "" {
		subs, _ = s.store.Subscriptions(ctx, tenant)
	}
	tp, _ := s.store.TypePolicies(ctx)

	d := adminData{User: u, Tenant: tenant, Users: users, Protected: prot,
		Subscriptions: subs, TypePolicies: tp, Enabled: s.auth.Enabled, OptIns: map[string]bool{},
		Notice: r.URL.Query().Get("err")}
	if tenant != "" {
		_ = s.store.EnsureTierDefaults(ctx, tenant)
		d.Grant = s.store.GrantReadinessAt(ctx, tenant, time.Now())
		d.GrantSP, _ = s.store.GrantSP(ctx, tenant)
		d.TierPolicy, _ = s.store.TierPolicies(ctx, tenant)
		if optins, _ := s.store.ScopeOptIns(ctx, tenant, store.ModuleGrant); optins != nil {
			for _, sc := range optins {
				d.OptIns[sc] = true
			}
		}
	}
	s.render(w, "admin.html", d)
}

// adminModule toggles the tenant-wide self-service-grant capability. Global admin
// only; audited. States: configuring | live | disabled.
func (s *Server) adminModule(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	tenant := s.adminTenant(r)
	_ = r.ParseForm()
	state := r.FormValue("state")
	switch state {
	case "configuring", "live", "disabled", "off":
		// Fail-closed: refuse to go 'live' unless every other gate is green.
		if state == "live" {
			rd := s.store.GrantReadinessAt(r.Context(), tenant, time.Now())
			var missing []string
			if !rd.SPVerified {
				missing = append(missing, "grant SP verification")
			}
			if !rd.TiersAck {
				missing = append(missing, "tier-policy review")
			}
			if rd.CatalogCount == 0 {
				missing = append(missing, "requestable catalog roles")
			}
			if rd.ScopeOptIns == 0 {
				missing = append(missing, "a subscription opt-in")
			}
			if len(missing) > 0 {
				msg := "Can't go live yet — still needed: " + strings.Join(missing, ", ") + "."
				http.Redirect(w, r, "/admin?err="+url.QueryEscape(msg), http.StatusSeeOther)
				return
			}
		}
		_ = s.store.SetModuleState(r.Context(), tenant, store.ModuleGrant, state, u.Email)
		s.store.Audit(r.Context(), tenant, u.Email, "grant_module_"+state, nil)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// adminGrantSP records the write-capable grant SP's NON-secret identity. Global
// admin only. Storing new config clears any prior readiness verification.
func (s *Server) adminGrantSP(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	tenant := s.adminTenant(r)
	_ = r.ParseForm()
	cfg := store.GrantSPConfig{
		AppID:      r.FormValue("app_id"),
		SPTenantID: r.FormValue("sp_tenant_id"),
		CredRef:    r.FormValue("cred_ref"),
		RootScope:  r.FormValue("root_scope"),
	}
	if cfg.AppID == "" || cfg.SPTenantID == "" || cfg.CredRef == "" || cfg.RootScope == "" {
		http.Error(w, "app id, SP tenant, credential reference and root scope are all required", http.StatusBadRequest)
		return
	}
	_ = s.store.SetGrantSP(r.Context(), tenant, cfg, u.Email)
	s.store.Audit(r.Context(), tenant, u.Email, "grant_sp_configured",
		map[string]any{"app_id": cfg.AppID, "root_scope": cfg.RootScope})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// adminGrantSPProbe runs the read-only readiness probe against the configured
// grant SP and records the outcome (fail-closed). Global admin only.
func (s *Server) adminGrantSPProbe(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	tenant := s.adminTenant(r)
	cfg, _ := s.store.GrantSP(r.Context(), tenant)
	redirect := func(msg string) { http.Redirect(w, r, "/admin?err="+url.QueryEscape(msg), http.StatusSeeOther) }
	if !cfg.Configured() {
		redirect("Configure the grant service principal before probing.")
		return
	}
	// The credential itself is never stored — cred_ref names the env var holding
	// the certificate PEM path in this deployment.
	certPath := os.Getenv(cfg.CredRef)
	if certPath == "" {
		_ = s.store.MarkGrantSPProbe(r.Context(), tenant, false, "credential ref '"+cfg.CredRef+"' not set in this deployment's environment")
		redirect("Probe failed: credential reference '" + cfg.CredRef + "' is not set in the environment.")
		return
	}
	sp, err := collect.NewSP(cfg.SPTenantID, cfg.AppID, certPath)
	if err != nil {
		_ = s.store.MarkGrantSPProbe(r.Context(), tenant, false, "cannot load certificate: "+err.Error())
		redirect("Probe failed: " + err.Error())
		return
	}
	okProbe, note := collect.ProbeGrantSP(r.Context(), sp, cfg.RootScope)
	_ = s.store.MarkGrantSPProbe(r.Context(), tenant, okProbe, note)
	s.store.Audit(r.Context(), tenant, u.Email, "grant_sp_probe",
		map[string]any{"ok": okProbe, "note": note})
	if okProbe {
		http.Redirect(w, r, "/admin#ssar", http.StatusSeeOther)
	} else {
		redirect("Grant SP probe: " + note)
	}
}

// adminTierPolicy updates one tier's knobs. Global admin only (tenant-wide policy);
// saving stamps acknowledgement (gate 3).
func (s *Server) adminTierPolicy(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	tenant := s.adminTenant(r)
	_ = r.ParseForm()
	tier := r.FormValue("tier")
	if tier != "low" && tier != "medium" && tier != "privileged" {
		http.Error(w, "unknown tier", http.StatusBadRequest)
		return
	}
	approver := r.FormValue("approver_tier")
	if approver != "global" {
		approver = "scoped"
	}
	t := store.TierPolicy{
		Tier:           tier,
		SelfService:    r.FormValue("self_service") == "on",
		DefaultDays:    atoiSafe(r.FormValue("default_days")),
		MaxDays:        atoiSafe(r.FormValue("max_days")),
		AllowPermanent: r.FormValue("allow_permanent") == "on",
		ApproverTier:   approver,
	}
	_ = s.store.SetTierPolicy(r.Context(), tenant, t, u.Email)
	s.store.Audit(r.Context(), tenant, u.Email, "grant_tier_policy_changed",
		map[string]any{"tier": tier, "self_service": t.SelfService, "max_days": t.MaxDays})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// adminScopeOptIn opts a subscription in/out of the module. Global admin or that
// subscription's admin.
func (s *Server) adminScopeOptIn(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "anyadmin")
	if !ok {
		return
	}
	tenant := s.adminTenant(r)
	_ = r.ParseForm()
	scope := r.FormValue("scope")
	if scope == "" || scope == "*" || !canAdminScope(u, scope) {
		http.Error(w, "forbidden: you may not manage that scope", http.StatusForbidden)
		return
	}
	enabled := r.FormValue("enabled") == "on"
	_ = s.store.SetScopeOptIn(r.Context(), tenant, scope, store.ModuleGrant, enabled, u.Email)
	s.store.Audit(r.Context(), tenant, u.Email, "grant_scope_optin",
		map[string]any{"scope": scope, "enabled": enabled})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func atoiSafe(v string) int {
	n, _ := strconv.Atoi(v)
	if n < 0 {
		return 0
	}
	return n
}

func (s *Server) adminTypePolicy(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin") // tenant-wide policy → global admin only
	if !ok {
		return
	}
	_ = r.ParseForm()
	ptype, policy := r.FormValue("type"), r.FormValue("policy")
	switch ptype {
	case "User", "Group", "ServicePrincipal":
		_ = s.store.SetTypePolicy(r.Context(), ptype, policy, u.Email)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// canAdminScope authorizes granting/revoking at a scope: global scope needs a
// global admin; a subscription scope needs global admin or that sub's admin.
func canAdminScope(u *auth.User, scope string) bool {
	if scope == "*" || scope == "" {
		return u.IsAdmin()
	}
	return u.IsAdminOf(scope)
}

func (s *Server) adminGrant(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "anyadmin")
	if !ok {
		return
	}
	_ = r.ParseForm()
	email, role, scope := r.FormValue("email"), r.FormValue("role"), r.FormValue("scope")
	if scope == "" {
		scope = "*"
	}
	if email == "" || (role != "admin" && role != "approver") {
		http.Error(w, "email and a valid role are required", http.StatusBadRequest)
		return
	}
	if !canAdminScope(u, scope) {
		http.Error(w, "forbidden: you may not manage that scope", http.StatusForbidden)
		return
	}
	_ = s.store.GrantScopedRole(r.Context(), email, scope, role, u.Email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "anyadmin")
	if !ok {
		return
	}
	_ = r.ParseForm()
	email, role, scope := r.FormValue("email"), r.FormValue("role"), r.FormValue("scope")
	if !canAdminScope(u, scope) {
		http.Error(w, "forbidden: you may not manage that scope", http.StatusForbidden)
		return
	}
	if email != "" && role != "" && scope != "" {
		_ = s.store.RevokeScopedRole(r.Context(), email, scope, role)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminProtect(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin") // protected-role policy is tenant-wide → global admin
	if !ok {
		return
	}
	_ = r.ParseForm()
	if role := r.FormValue("role"); role != "" {
		_ = s.store.AddProtectedRole(r.Context(), role, u.Email)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminUnprotect(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	_ = r.ParseForm()
	if role := r.FormValue("role"); role != "" {
		_ = s.store.RemoveProtectedRole(r.Context(), role)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

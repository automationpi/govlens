package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// CatalogRole is one auto-discovered grantable role definition.
type CatalogRole struct {
	RoleDefID, RoleName, RoleKind string // role_kind: rbac | entra_role
	IsCustom, Deprecated          bool
	Tier, TierReason              string // set by ClassifyTier
}

// ClassifyTier deterministically tiers a role from its permissions (never its
// name — a custom role can be named "Reader" and carry write). Fail-closed:
// anything not clearly read-only or clearly privileged lands in medium, and a role
// with no parseable actions is treated as privileged. See docs/SELF-SERVICE-GRANT.md §3.
func ClassifyTier(actions, dataActions []string) (tier, reason string) {
	if len(actions) == 0 && len(dataActions) == 0 {
		return "privileged", "no parseable actions (fail-closed)"
	}
	for _, a := range actions {
		a = strings.TrimSpace(a)
		la := strings.ToLower(a)
		switch {
		case a == "*":
			return "privileged", "wildcard action '*'"
		case la == "microsoft.authorization/*":
			// Bare wildcard over authorization = full access management (includes write).
			return "privileged", "Microsoft.Authorization/* (full access management)"
		case strings.HasPrefix(la, "microsoft.authorization/") &&
			(strings.HasSuffix(la, "/write") || strings.HasSuffix(la, "/delete")):
			// A write/delete on any authorization resource can grant access.
			// Note: "Microsoft.Authorization/*/read" is read-only and does NOT match.
			return "privileged", "can write/delete access (" + a + ")"
		}
	}
	// Read-only only if EVERY management + data action is a read.
	allRead := true
	for _, a := range append(append([]string{}, actions...), dataActions...) {
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "" {
			continue
		}
		if !strings.HasSuffix(la, "/read") && la != "*/read" {
			allRead = false
			break
		}
	}
	if allRead {
		return "low", "read-only"
	}
	return "medium", "has non-read actions"
}

// Module names.
const (
	ModuleRevoke = "revoke"
	ModuleGrant  = "self_service_grant"
)

// spVerifyTTL is how long a grant-SP readiness probe stays valid; a stale probe
// closes the module (fail-closed). See docs/SELF-SERVICE-GRANT.md.
const spVerifyTTL = 24 * time.Hour

// ---- module flags -------------------------------------------------------------

// ModuleState returns the tenant-wide capability state ('*' row) for a module.
// Returns "off" when no row exists yet.
func (s *Store) ModuleState(ctx context.Context, tenant, module string) (string, error) {
	var state string
	err := s.Pool.QueryRow(ctx,
		`SELECT state FROM module_settings WHERE tenant=$1 AND scope='*' AND module=$2`,
		tenant, module).Scan(&state)
	if err != nil {
		return "off", nil //nolint: absent row = off
	}
	return state, nil
}

// SetModuleState upserts the tenant-wide capability state for a module.
func (s *Store) SetModuleState(ctx context.Context, tenant, module, state, by string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO module_settings (tenant, scope, module, enabled, state, enabled_by, enabled_at)
		VALUES ($1,'*',$2,$3,$4,$5,now())
		ON CONFLICT (tenant, scope, module)
		DO UPDATE SET enabled=EXCLUDED.enabled, state=EXCLUDED.state,
		              enabled_by=EXCLUDED.enabled_by, enabled_at=now()`,
		tenant, module, state == "live", state, by)
	return err
}

// ScopeOptIns returns the subscription scopes that have opted into a module.
func (s *Store) ScopeOptIns(ctx context.Context, tenant, module string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT scope FROM module_settings
		 WHERE tenant=$1 AND module=$2 AND scope<>'*' AND enabled=true
		 ORDER BY scope`, tenant, module)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// SetScopeOptIn enables/disables a subscription's opt-in for a module.
func (s *Store) SetScopeOptIn(ctx context.Context, tenant, scope, module string, enabled bool, by string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO module_settings (tenant, scope, module, enabled, state, enabled_by, enabled_at)
		VALUES ($1,$2,$3,$4,'', $5, now())
		ON CONFLICT (tenant, scope, module)
		DO UPDATE SET enabled=EXCLUDED.enabled, enabled_by=EXCLUDED.enabled_by, enabled_at=now()`,
		tenant, scope, module, enabled, by)
	return err
}

// ---- grant service principal --------------------------------------------------

// GrantSPConfig is the non-secret record of the write-capable grant SP.
type GrantSPConfig struct {
	AppID, SPTenantID, CredRef, RootScope string
	ConfiguredBy                          string
	ConfiguredAt                          time.Time
	LastVerified                          time.Time // zero = never
	ProbeNote                             string
}

// Configured reports whether an SP identity has been recorded.
func (g GrantSPConfig) Configured() bool { return g.AppID != "" }

// Verified reports whether the last readiness probe is present and within TTL.
func (g GrantSPConfig) Verified(now time.Time) bool {
	return !g.LastVerified.IsZero() && now.Sub(g.LastVerified) < spVerifyTTL
}

// GrantSP returns the configured grant SP (zero value if none).
func (s *Store) GrantSP(ctx context.Context, tenant string) (GrantSPConfig, error) {
	var g GrantSPConfig
	var lastVerified *time.Time
	err := s.Pool.QueryRow(ctx, `
		SELECT app_id, sp_tenant_id, cred_ref, root_scope,
		       COALESCE(configured_by,''), COALESCE(configured_at, to_timestamp(0)),
		       last_verified, COALESCE(probe_note,'')
		  FROM grant_sp WHERE tenant=$1`, tenant).
		Scan(&g.AppID, &g.SPTenantID, &g.CredRef, &g.RootScope,
			&g.ConfiguredBy, &g.ConfiguredAt, &lastVerified, &g.ProbeNote)
	if err != nil {
		return GrantSPConfig{}, nil // no row = not configured
	}
	if lastVerified != nil {
		g.LastVerified = *lastVerified
	}
	return g, nil
}

// SetGrantSP records the SP identity (never a secret). Clears prior verification.
func (s *Store) SetGrantSP(ctx context.Context, tenant string, g GrantSPConfig, by string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO grant_sp (tenant, app_id, sp_tenant_id, cred_ref, root_scope, configured_by, configured_at)
		VALUES ($1,$2,$3,$4,$5,$6,now())
		ON CONFLICT (tenant) DO UPDATE SET
		  app_id=EXCLUDED.app_id, sp_tenant_id=EXCLUDED.sp_tenant_id, cred_ref=EXCLUDED.cred_ref,
		  root_scope=EXCLUDED.root_scope, configured_by=EXCLUDED.configured_by, configured_at=now(),
		  last_verified=NULL, probe_note='configured — awaiting readiness probe'`,
		tenant, g.AppID, g.SPTenantID, g.CredRef, g.RootScope, by)
	return err
}

// MarkGrantSPProbe records the outcome of a readiness probe. ok=true stamps
// last_verified=now(); ok=false clears it (fail-closed) with the failure note.
func (s *Store) MarkGrantSPProbe(ctx context.Context, tenant string, ok bool, note string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE grant_sp
		   SET last_verified = CASE WHEN $2 THEN now() ELSE NULL END,
		       probe_note = $3
		 WHERE tenant=$1`, tenant, ok, note)
	return err
}

// ---- tier policy --------------------------------------------------------------

// TierPolicy is the per-tier grant policy (the knobs an admin tunes).
type TierPolicy struct {
	Tier           string
	SelfService    bool
	DefaultDays    int // 0 = unset
	MaxDays        int // 0 = uncapped
	AllowPermanent bool
	ApproverTier   string // scoped | global
	Acknowledged   bool
}

// tierDefaults are the safe seeds (privileged is hidden). See docs §2.4.
var tierDefaults = []TierPolicy{
	{Tier: "low", SelfService: true, DefaultDays: 90, MaxDays: 0, AllowPermanent: true, ApproverTier: "scoped"},
	{Tier: "medium", SelfService: true, DefaultDays: 30, MaxDays: 90, AllowPermanent: false, ApproverTier: "scoped"},
	{Tier: "privileged", SelfService: false, DefaultDays: 7, MaxDays: 7, AllowPermanent: false, ApproverTier: "global"},
}

// EnsureTierDefaults seeds the three tier rows for a tenant if absent (idempotent).
func (s *Store) EnsureTierDefaults(ctx context.Context, tenant string) error {
	for _, d := range tierDefaults {
		if _, err := s.Pool.Exec(ctx, `
			INSERT INTO grant_tier_policy
			  (tenant, tier, self_service, default_days, max_days, allow_permanent, approver_tier)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant, tier) DO NOTHING`,
			tenant, d.Tier, d.SelfService, nz(d.DefaultDays), nz(d.MaxDays), d.AllowPermanent, d.ApproverTier); err != nil {
			return err
		}
	}
	return nil
}

// TierPolicies returns the tenant's tier policies in low→medium→privileged order.
func (s *Store) TierPolicies(ctx context.Context, tenant string) ([]TierPolicy, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT tier, self_service, COALESCE(default_days,0), COALESCE(max_days,0),
		       allow_permanent, approver_tier, ack_by IS NOT NULL
		  FROM grant_tier_policy WHERE tenant=$1
		 ORDER BY CASE tier WHEN 'low' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TierPolicy
	for rows.Next() {
		var t TierPolicy
		if err := rows.Scan(&t.Tier, &t.SelfService, &t.DefaultDays, &t.MaxDays,
			&t.AllowPermanent, &t.ApproverTier, &t.Acknowledged); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetTierPolicy updates one tier's knobs and stamps acknowledgement.
func (s *Store) SetTierPolicy(ctx context.Context, tenant string, t TierPolicy, by string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE grant_tier_policy
		   SET self_service=$3, default_days=$4, max_days=$5, allow_permanent=$6,
		       approver_tier=$7, ack_by=$8, ack_at=now()
		 WHERE tenant=$1 AND tier=$2`,
		tenant, t.Tier, t.SelfService, nz(t.DefaultDays), nz(t.MaxDays),
		t.AllowPermanent, t.ApproverTier, by)
	return err
}

// AllTiersAcknowledged reports whether every tier row has been reviewed (gate 3).
func (s *Store) AllTiersAcknowledged(ctx context.Context, tenant string) bool {
	var missing int
	_ = s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM grant_tier_policy WHERE tenant=$1 AND ack_by IS NULL`, tenant).Scan(&missing)
	return missing == 0
}

// RequestableCatalogCount counts roles currently exposable for self-service
// (tier allows OR an allow-override), minus deny-overrides and deprecated roles.
func (s *Store) RequestableCatalogCount(ctx context.Context, tenant string) int {
	var n int
	_ = s.Pool.QueryRow(ctx, `
		SELECT count(*)
		  FROM role_catalog c
		  LEFT JOIN grant_tier_policy p ON p.tenant=c.tenant AND p.tier=c.tier
		  LEFT JOIN catalog_override o ON o.tenant=c.tenant AND o.role_def_id=c.role_def_id
		 WHERE c.tenant=$1 AND c.deprecated=false
		   AND COALESCE(o.decision,'') <> 'deny'
		   AND (o.decision='allow' OR p.self_service=true)`, tenant).Scan(&n)
	return n
}

// ---- audit --------------------------------------------------------------------

// Audit records a privileged admin action. detail is marshalled to JSONB.
func (s *Store) Audit(ctx context.Context, tenant, actor, action string, detail map[string]any) {
	var raw []byte
	if detail != nil {
		raw, _ = json.Marshal(detail)
	}
	_, _ = s.Pool.Exec(ctx,
		`INSERT INTO admin_audit (tenant, actor, action, detail) VALUES ($1,$2,$3,$4)`,
		tenant, actor, action, raw)
}

// ---- readiness resolver -------------------------------------------------------

// GrantReadiness is the enablement-gate snapshot shown on the admin page and used
// to decide whether the module is live. See docs/SELF-SERVICE-GRANT.md §1.
type GrantReadiness struct {
	CapabilityState string // off | configuring | live | disabled
	SPConfigured    bool
	SPVerified      bool
	SPNote          string
	TiersAck        bool
	CatalogCount    int
	ScopeOptIns     int
	Live            bool // overall: intake open tenant-wide?
}

// GrantReadinessAt computes the gate snapshot for a tenant. `now` is injected so
// the 24h SP-verification TTL is testable.
func (s *Store) GrantReadinessAt(ctx context.Context, tenant string, now time.Time) GrantReadiness {
	var r GrantReadiness
	r.CapabilityState, _ = s.ModuleState(ctx, tenant, ModuleGrant)
	sp, _ := s.GrantSP(ctx, tenant)
	r.SPConfigured = sp.Configured()
	r.SPVerified = sp.Verified(now)
	r.SPNote = sp.ProbeNote
	r.TiersAck = s.AllTiersAcknowledged(ctx, tenant)
	r.CatalogCount = s.RequestableCatalogCount(ctx, tenant)
	if optins, _ := s.ScopeOptIns(ctx, tenant, ModuleGrant); optins != nil {
		r.ScopeOptIns = len(optins)
	}
	// Fail-closed: every gate must pass for intake to be live.
	r.Live = r.CapabilityState == "live" && r.SPVerified &&
		r.TiersAck && r.CatalogCount > 0 && r.ScopeOptIns > 0
	return r
}

// nz maps 0 → NULL for nullable integer columns.
func nz(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

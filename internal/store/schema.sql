-- azure-govlens schema. Thin but real: one row per collection run, plus
-- flexible time-series metrics, per-control findings, and assignments for drift.

CREATE TABLE IF NOT EXISTS runs (
    id           BIGSERIAL PRIMARY KEY,
    tenant       TEXT        NOT NULL DEFAULT 'default',
    collected_at TIMESTAMPTZ NOT NULL,
    source_label TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant, collected_at)
);

-- Collection provenance: which collectors actually contributed to this run.
-- Used to suppress false drift when a collector silently failed (a missing
-- source must not read as a mass-removal of everything it would have reported).
ALTER TABLE runs ADD COLUMN IF NOT EXISTS sources TEXT[] NOT NULL DEFAULT '{}';

-- tenant is the stable identity (the Entra tenant id); tenant_display is the
-- human name (e.g. "Example Org") shown in the UI. Keyed by id so the same
-- Azure directory can never fork into multiple labels.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS tenant_display TEXT NOT NULL DEFAULT '';

-- Access-request workflow queue (revoke today; grant once the self-service module
-- is enabled) — also the audit trail. The web app only writes rows here (no Azure
-- permission needed); separate write-capable workers process 'approved' rows.
--   pending  -> approved | rejected                        (2-stage human review)
--   approved -> processing -> done|failed|skipped          (revoke worker)
--   approved -> granted (expires_at) -> expiry sweep -> revoke   (grant worker; see
--                                        docs/SELF-SERVICE-GRANT.md)
-- Migrate the original revoke_requests table in place (no-op on fresh DBs).
ALTER TABLE IF EXISTS revoke_requests RENAME TO access_requests;
CREATE TABLE IF NOT EXISTS access_requests (
    id             BIGSERIAL PRIMARY KEY,
    tenant         TEXT NOT NULL,
    run_id         BIGINT REFERENCES runs(id) ON DELETE SET NULL,
    kind           TEXT NOT NULL,                 -- rbac | entra_role | ca_policy
    target_ident   TEXT NOT NULL,                 -- the assignment id (revoke: existing; grant: created)
    principal      TEXT,
    principal_type TEXT,
    role           TEXT,
    scope          TEXT,
    reason         TEXT,
    requested_by   TEXT NOT NULL DEFAULT 'unknown',
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    status         TEXT NOT NULL DEFAULT 'pending',
    decided_by     TEXT,
    decided_at     TIMESTAMPTZ,
    decision_note  TEXT,
    processed_at   TIMESTAMPTZ,
    result         TEXT
);
-- Grant-path columns (additive; existing revoke rows default action='revoke').
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS action         TEXT NOT NULL DEFAULT 'revoke'; -- grant | revoke
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS role_def_id    TEXT;        -- grant: roleDefinition guid to assign
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS principal_oid  TEXT;        -- grant: target principal object id (from OIDC oid)
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS requested_days INTEGER;     -- requester's proposed duration
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS requested_permanent BOOLEAN NOT NULL DEFAULT false; -- requester asked for no expiry
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS expires_at     TIMESTAMPTZ; -- set at approval; NULL = permanent
CREATE INDEX IF NOT EXISTS idx_revoke_tenant_status ON access_requests(tenant, status);
CREATE INDEX IF NOT EXISTS idx_access_expiry ON access_requests(expires_at)
    WHERE action='grant' AND status='granted' AND expires_at IS NOT NULL;

-- App users + their in-app roles (admin, approver). Populated on first login;
-- roles granted via the admin page. Bootstrap admins come from GOVLENS_ADMIN_EMAILS.
CREATE TABLE IF NOT EXISTS app_users (
    email      TEXT PRIMARY KEY,
    name       TEXT,
    roles      TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Subscriptions seen by the collector, for the selector + friendly names.
CREATE TABLE IF NOT EXISTS subscriptions (
    tenant TEXT NOT NULL,
    sub_id TEXT NOT NULL,
    name   TEXT,
    PRIMARY KEY (tenant, sub_id)
);

-- Resource groups discovered under each subscription, for scoping grant requests
-- below the subscription level. Refreshed per collection run.
CREATE TABLE IF NOT EXISTS resource_groups (
    tenant    TEXT NOT NULL,
    sub_id    TEXT NOT NULL,
    name      TEXT NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, sub_id, name)
);

-- Scoped role grants: scope '*' = tenant-wide (global), else a subscription id.
-- Roles: admin | approver. This supersedes app_users.roles (migrated once below).
CREATE TABLE IF NOT EXISTS user_scope_roles (
    email    TEXT NOT NULL,
    scope    TEXT NOT NULL,
    role     TEXT NOT NULL,
    added_by TEXT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (email, scope, role)
);
INSERT INTO user_scope_roles (email, scope, role, added_by)
    SELECT email, '*', unnest(roles), 'migrated' FROM app_users
     WHERE array_length(roles,1) > 0 AND NOT EXISTS (SELECT 1 FROM user_scope_roles)
    ON CONFLICT DO NOTHING;

-- Roles that must never be revoked through this tool (configurable in admin).
-- Enforced in the UI (no Revoke button), the mark endpoint, and the worker.
CREATE TABLE IF NOT EXISTS protected_roles (
    role     TEXT PRIMARY KEY,
    added_by TEXT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO protected_roles (role, added_by) VALUES ('Global Administrator', 'system')
    ON CONFLICT DO NOTHING;

-- Per-principal-type revocation policy (set by a global admin). Absent = allow.
--   blocked = never revocable through this tool
--   global  = revocation requires a GLOBAL approver/admin (not a scoped approver)
CREATE TABLE IF NOT EXISTS type_policies (
    principal_type TEXT PRIMARY KEY,   -- User | Group | ServicePrincipal
    policy         TEXT NOT NULL,      -- blocked | global
    set_by         TEXT,
    set_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- At most one open request per target (prevents double-marking the same assignment).
-- Recreated with a target_ident<>'' guard so grant rows (which have no ident until
-- provisioned) don't collide on the empty string.
DROP INDEX IF EXISTS uq_revoke_open_target;
CREATE UNIQUE INDEX IF NOT EXISTS uq_revoke_open_target
    ON access_requests(tenant, target_ident)
    WHERE status IN ('pending','approved','processing') AND target_ident <> '';

-- Flexible metrics for trend charts (compliance %, pass rates, counts).
CREATE TABLE IF NOT EXISTS metrics (
    run_id   BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    domain   TEXT   NOT NULL,             -- azure | entra
    category TEXT   NOT NULL,             -- policy_compliance | maester | ca_policy
    key      TEXT   NOT NULL,             -- compliant | non_compliant | passed | failed ...
    value    DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (run_id, domain, category, key)
);

-- Individual control results: Azure Policy compliance rows + Maester tests.
CREATE TABLE IF NOT EXISTS findings (
    id         BIGSERIAL PRIMARY KEY,
    run_id     BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    domain     TEXT   NOT NULL,           -- azure | entra
    source     TEXT   NOT NULL,           -- azgovviz-policy | maester
    control_id TEXT   NOT NULL,           -- policy assignment id / MT.xxxx
    title      TEXT   NOT NULL,
    severity   TEXT,                      -- High | Medium | Low | Info
    status     TEXT   NOT NULL,           -- compliant|non_compliant | passed|failed|notrun
    category   TEXT,
    scope      TEXT,
    help_url   TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_run    ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Assignments captured as state each run, so we can diff consecutive runs (drift).
-- kind=rbac  -> Azure role assignments (from AzGovViz)
-- kind=ca_policy -> Entra Conditional Access policies (from EntraExporter)
CREATE TABLE IF NOT EXISTS assignments (
    run_id         BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    domain         TEXT   NOT NULL,       -- azure | entra
    kind           TEXT   NOT NULL,       -- rbac | ca_policy
    ident          TEXT   NOT NULL,       -- stable key used for diffing across runs
    principal      TEXT,
    principal_type TEXT,
    role           TEXT,                  -- role name (rbac) | policy state (ca)
    scope          TEXT,
    display        TEXT,                  -- human-readable label
    PRIMARY KEY (run_id, kind, ident)
);
CREATE INDEX IF NOT EXISTS idx_assign_run  ON assignments(run_id);
CREATE INDEX IF NOT EXISTS idx_assign_kind ON assignments(kind, ident);

-- ============================================================================
-- Self-service access-request (grant) module — opt-in, off by default.
-- See docs/SELF-SERVICE-GRANT.md for the enablement checklist + full design.
-- ============================================================================

-- Module flags. scope='*' is the tenant-wide capability switch (global admin only,
-- carries the lifecycle `state`); scope=<sub id> is a per-subscription opt-in.
CREATE TABLE IF NOT EXISTS module_settings (
    tenant     TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '*',       -- '*' = tenant-wide, else subscription id
    module     TEXT NOT NULL,                   -- 'revoke' | 'self_service_grant'
    enabled    BOOLEAN NOT NULL DEFAULT false,
    state      TEXT NOT NULL DEFAULT 'off',     -- off | configuring | live | disabled ('*' row)
    enabled_by TEXT,
    enabled_at TIMESTAMPTZ,
    PRIMARY KEY (tenant, scope, module)
);

-- The write-capable grant SP — NON-secret identity + probe outcome only. The actual
-- credential lives in env / secret store, referenced by cred_ref.
CREATE TABLE IF NOT EXISTS grant_sp (
    tenant        TEXT PRIMARY KEY,
    app_id        TEXT NOT NULL,                -- client id (public)
    sp_tenant_id  TEXT NOT NULL,
    cred_ref      TEXT NOT NULL,                -- name of env var / secret holding the PEM, NOT the PEM
    root_scope    TEXT NOT NULL,                -- MG/sub the SP may write within
    configured_by TEXT,
    configured_at TIMESTAMPTZ,
    last_verified TIMESTAMPTZ,                  -- last successful auth + permission probe (24h TTL)
    probe_note    TEXT
);

-- Role catalog — auto-discovered from Azure roleDefinitions each collect, tier is a
-- deterministic function of the role's actions (see docs §3). Populated later.
CREATE TABLE IF NOT EXISTS role_catalog (
    tenant      TEXT NOT NULL,
    role_def_id TEXT NOT NULL,                  -- roleDefinitionId (guid) — dedupe key
    role_name   TEXT NOT NULL,
    role_kind   TEXT NOT NULL DEFAULT 'rbac',   -- rbac | entra_role
    is_custom   BOOLEAN NOT NULL DEFAULT false,
    deprecated  BOOLEAN NOT NULL DEFAULT false,
    tier        TEXT NOT NULL,                  -- low | medium | privileged
    tier_reason TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, role_def_id)
);

-- Per-tier policy — the handful of knobs an admin tunes; every role inherits via tier.
CREATE TABLE IF NOT EXISTS grant_tier_policy (
    tenant          TEXT NOT NULL,
    tier            TEXT NOT NULL,              -- low | medium | privileged
    self_service    BOOLEAN NOT NULL,
    default_days    INTEGER,                    -- pre-fills approver's expiry picker
    max_days        INTEGER,                    -- ceiling approver can't exceed (NULL = uncapped)
    allow_permanent BOOLEAN NOT NULL DEFAULT false,
    approver_tier   TEXT NOT NULL DEFAULT 'scoped', -- 'scoped' | 'global'
    ack_by          TEXT,                       -- who acknowledged (gate 3)
    ack_at          TIMESTAMPTZ,
    PRIMARY KEY (tenant, tier)
);

-- Small exception overlay: force a role requestable ('allow') or hidden ('deny').
CREATE TABLE IF NOT EXISTS catalog_override (
    tenant        TEXT NOT NULL,
    role_def_id   TEXT NOT NULL,
    decision      TEXT NOT NULL,                -- 'allow' | 'deny'
    scope_pattern TEXT,
    note          TEXT,
    set_by        TEXT,
    set_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, role_def_id)
);

-- Audit trail for the sensitive admin actions (module toggles, SP wiring, policy).
CREATE TABLE IF NOT EXISTS admin_audit (
    id     BIGSERIAL PRIMARY KEY,
    tenant TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail JSONB,
    at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_tenant ON admin_audit(tenant, at DESC);

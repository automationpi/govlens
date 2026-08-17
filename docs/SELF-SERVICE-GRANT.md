# Self-Service Access Requests - Enablement Checklist & Settings Schema

> **Status:** design draft (not yet implemented). Opt-in module, off by default.
> Extends the existing review→approve→worker flow from *revoke* to *grant*.
>
> **Confirmed decisions:**
> 1. Standardize the queue table name on **`access_requests`** (rename from `revoke_requests`).
>    Implementation note: this touches the running revoke code - `internal/store/revoke.go`,
>    `queries.go`, and every `revoke_requests` reference - so do it as one rename commit with a
>    compatibility view (`CREATE VIEW revoke_requests AS SELECT * FROM access_requests`) if a
>    staged cutover is wanted.
> 2. Seeded tier defaults per §2.4 - **`privileged` is hidden** (not self-service), medium/low as shown.
> 3. Grant SP readiness re-probed on a **24h TTL**; a stale probe closes the module (fail-closed).

The self-service grant module lets any signed-in user **request** new access from an
admin-curated catalog; requests run through the **same approval flow** as revoke, and a
**write-capable worker** provisions the grant - time-bound by default. It is a bigger
escalation than revoke (granting *adds* privilege), so it is **opt-in, global-admin-gated,
and fail-closed**: nothing is live until every enablement gate is green.

Two independent module flags - an org can run *revoke* without ever enabling *grant*:

| Module | Flag key | What it does |
|---|---|---|
| Review / Revoke | `revoke` | (already live) mark → review → worker deletes |
| Self-service grant | `self_service_grant` | request → review → worker **creates** a time-bound assignment |

---

## 1. Enablement checklist (fail-closed gates)

The admin UI walks a **global admin** through these in order. The module is not *live*
for a scope until **all** gates pass; a partially-configured module keeps intake **closed**
(users see nothing) rather than accepting requests that would fail at the worker.

| # | Gate | Precondition to pass | Backing check |
|---|---|---|---|
| 0 | **Authority** | Actor is a global admin (`scope='*'` admin grant). | `auth.IsAdmin` |
| 1 | **Capability on** | Global admin toggles the tenant-wide capability. Writes a `module_settings('*')` row in state `configuring`. | row exists, `state='configuring'` |
| 2 | **Grant SP wired** | Enter the grant SP's app id / tenant / credential reference. System runs a **live probe**: (a) authenticates, (b) confirms it holds `roleAssignments/write` at the intended root, (c) confirms it is **not** over-permissioned (no `*` / `Owner` / broader than needed). | `grant_sp.last_verified` set, probe OK |
| 3 | **Tier policy acknowledged** | Review the 4 knobs per tier (`self_service`, `default_days`, `max_days`, `allow_permanent`, `approver_tier`). Privileged-tier settings require an explicit confirm. | `grant_tier_policy` has all 3 tiers, `ack_by` set |
| 4 | **Catalog built** | Run a collect to auto-populate `role_catalog`; review auto-classification; add any `catalog_override`. Must yield **≥1** self-service entry. | `count(requestable) ≥ 1` |
| 5 | **Scope opt-in** | Choose exposure: tenant-wide, or per-subscription (sub admins opt their own sub in later). | ≥1 enabled `module_settings` scope row |
| 6 | **Go live** | Flip capability `state='live'`. Audited (`admin_audit`). | `module_settings('*').state='live'` |

**Readiness resolver**: the module is *live for scope S* iff **all** hold:

```
capability('*').state = 'live'
AND grant_sp.last_verified within 24h TTL (re-probed on schedule; stale → module closes)
AND module_settings(S).enabled = true          -- S opted in ('*' counts for tenant-wide)
AND EXISTS a requestable catalog entry for S
```

Any false → intake closed for S (fail-closed). The resolver is evaluated on every request-
page load and again at submit time.

**Disable semantics** (set `enabled=false` or capability `state='disabled'`):
- **Stops new intake** immediately (request page hidden, submit rejected).
- **Never auto-revokes existing grants**: flipping a flag must not cause an access outage.
- Pending requests are frozen (approvers see "module disabled"); the **expiry sweep keeps
  running** so already-granted, time-bound access still expires on schedule.
- Audited.

---

## 2. Settings schema (proposed DDL)

Follows existing `schema.sql` conventions (snake_case, `TIMESTAMPTZ`, `IF NOT EXISTS`).
Secrets never live in the DB - only **references** to where the credential is held.

### 2.1 Module flags - capability + per-scope opt-in

```sql
-- One row per (tenant, scope, module). scope='*' is the tenant-wide capability
-- switch (global admin only); scope=<sub id> is a per-subscription opt-in (sub admin).
CREATE TABLE IF NOT EXISTS module_settings (
    tenant     TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '*',        -- '*' = tenant-wide, else subscription id
    module     TEXT NOT NULL,                    -- 'revoke' | 'self_service_grant'
    enabled    BOOLEAN NOT NULL DEFAULT false,
    state      TEXT NOT NULL DEFAULT 'off',       -- off | configuring | live | disabled ('*' row only)
    enabled_by TEXT,
    enabled_at TIMESTAMPTZ,
    PRIMARY KEY (tenant, scope, module)
);
```

### 2.2 Grant service principal - reference only, no secret

```sql
-- Records that a write-capable grant SP is configured, plus its NON-secret identity and
-- the outcome of the readiness probe. The actual cert/secret stays in env / secret store.
CREATE TABLE IF NOT EXISTS grant_sp (
    tenant        TEXT PRIMARY KEY,
    app_id        TEXT NOT NULL,                 -- client id (public)
    sp_tenant_id  TEXT NOT NULL,
    cred_ref      TEXT NOT NULL,                 -- name of env var / secret holding the PEM, NOT the PEM
    root_scope    TEXT NOT NULL,                 -- the MG/sub the SP may write within
    configured_by TEXT,
    configured_at TIMESTAMPTZ,
    last_verified TIMESTAMPTZ,                   -- last successful auth + permission probe
    probe_note    TEXT                           -- e.g. 'ok: roleAssignments/write @ sub, no broader'
);
```

### 2.3 Role catalog - auto-discovered, auto-tiered

```sql
-- Populated on every collect from Azure roleDefinitions (built-in + custom) and Entra
-- directory roles. tier is a deterministic function of the role's actions (see §3).
CREATE TABLE IF NOT EXISTS role_catalog (
    tenant      TEXT NOT NULL,
    role_def_id TEXT NOT NULL,                   -- Azure roleDefinitionId (guid) - dedupe key
    role_name   TEXT NOT NULL,
    role_kind   TEXT NOT NULL DEFAULT 'rbac',    -- rbac | entra_role
    is_custom   BOOLEAN NOT NULL DEFAULT false,
    deprecated  BOOLEAN NOT NULL DEFAULT false,  -- e.g. classic administrators - never requestable
    tier        TEXT NOT NULL,                   -- low | medium | privileged (auto)
    tier_reason TEXT,                            -- 'only */read' | 'has Microsoft.Authorization/*' ...
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, role_def_id)
);
```

### 2.4 Tier policy - the 4 knobs an admin actually tunes

```sql
-- One row per tier. This is where "less human intervention" comes from: admins set a
-- handful of rules once, and every current/future role inherits them via its tier.
CREATE TABLE IF NOT EXISTS grant_tier_policy (
    tenant          TEXT NOT NULL,
    tier            TEXT NOT NULL,               -- low | medium | privileged
    self_service    BOOLEAN NOT NULL,            -- requestable at all?
    default_days    INTEGER,                     -- pre-fills the approver's expiry picker
    max_days        INTEGER,                     -- ceiling the approver cannot exceed (NULL = uncapped)
    allow_permanent BOOLEAN NOT NULL DEFAULT false, -- may approver choose "no expiry"?
    approver_tier   TEXT NOT NULL DEFAULT 'scoped', -- 'scoped' (sub approver ok) | 'global'
    ack_by          TEXT,                        -- who confirmed (gate 3)
    PRIMARY KEY (tenant, tier)
);
```

**Suggested seeded defaults (safe, fail-closed for privileged):**

| tier | self_service | default_days | max_days | allow_permanent | approver_tier |
|---|---|---|---|---|---|
| `low` (read-only) | ✅ | 90 | - (uncapped) | ✅ | scoped |
| `medium` (data / contributor) | ✅ | 30 | 90 | ❌ | scoped |
| `privileged` (auth / `*`) | ❌ | 7 | 7 | ❌ | global |

### 2.5 Catalog overrides - the small exception overlay

```sql
-- Human effort is O(exceptions), not O(roles). 'deny' force-hides a role even if its tier
-- allows it; 'allow' force-exposes one the tier would hide (with eyes open).
CREATE TABLE IF NOT EXISTS catalog_override (
    tenant        TEXT NOT NULL,
    role_def_id   TEXT NOT NULL,
    decision      TEXT NOT NULL,                 -- 'allow' | 'deny'
    scope_pattern TEXT,                          -- optional: exact sub id, 'tag:env=test', or '*'
    note          TEXT,
    set_by        TEXT,
    set_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, role_def_id)
);
```

### 2.6 Request queue - generalize `revoke_requests` → `access_requests`

The workflow table gains an `action` and grant-specific columns. Existing revoke rows keep
working (`action` defaults to `'revoke'`); grant rows use `role_def_id` + `expires_at`.

```sql
-- Additive migration on the existing revoke_requests table:
ALTER TABLE revoke_requests RENAME TO access_requests;             -- decided: standardize on this name
ALTER TABLE access_requests ADD COLUMN action         TEXT NOT NULL DEFAULT 'revoke'; -- grant | revoke
ALTER TABLE access_requests ADD COLUMN role_def_id    TEXT;        -- grant: role to assign
ALTER TABLE access_requests ADD COLUMN requested_days INTEGER;     -- requester's proposed duration
ALTER TABLE access_requests ADD COLUMN expires_at     TIMESTAMPTZ; -- set at approval; NULL = permanent
-- For a grant, target_ident is EMPTY until provisioned, then holds the CREATED assignment id
-- (so the same row can later be expiry-revoked by ident, exactly like a normal revoke).

CREATE INDEX IF NOT EXISTS idx_access_expiry
    ON access_requests (expires_at)
    WHERE action='grant' AND status='granted' AND expires_at IS NOT NULL;
```

New statuses for the grant path: `granted` (worker created it), and reuse `failed`/`skipped`.
Expiry-revocation is a normal `action='revoke'` follow-up the worker enqueues, so the
timeline and audit stay uniform.

### 2.7 Admin audit - privileged actions are logged

```sql
-- Enabling/disabling the module, wiring the SP, and policy changes are the most sensitive
-- clicks in the product. Log all of them.
CREATE TABLE IF NOT EXISTS admin_audit (
    id     BIGSERIAL PRIMARY KEY,
    tenant TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,   -- module_enabled | module_disabled | grant_sp_configured
                            -- | tier_policy_changed | catalog_override_set | scope_opted_in
    detail JSONB,
    at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## 3. Deterministic tiering (how a role gets its tier)

Classification is a pure function of the role's `actions` / `notActions`, evaluated at
collect time - **not** the display name (names lie; a custom role can be named "Reader" and
carry write). Fail-closed: anything unclassifiable → `privileged` (i.e. not self-service).

```
if actions contains "*"                                  -> privileged  ("wildcard action")
if actions match "Microsoft.Authorization/.*roleAssignments/(write|delete)"
   or "Microsoft.Authorization/\*"                       -> privileged  ("can grant access")
if EVERY action ends in "/read" (and no data-plane write)-> low         ("read-only")
otherwise                                                -> medium
```

`deprecated=true` (classic administrators, retired roles) → never requestable, regardless of tier.

---

## 4. Worker changes (for reference)

The existing remediator loop gains one branch and one sweep - same SP-separation discipline:

- **Provision**: for `action='grant' AND status='approved'`: safety-gate (module live?
  catalog still allows this role+scope? tier policy still permits? within `max_days`?), then
  `PUT roleAssignments/{new-guid}` → on success write the created ident back and set
  `status='granted'`, `processed_at=now()`.
- **Expiry sweep**: `WHERE action='grant' AND status='granted' AND expires_at < now()` →
  enqueue an `action='revoke'` for the stored ident. NULL `expires_at` rows are never
  selected, so permanent grants are left alone automatically.

The grant SP is **separate** from both the read-only collector SP and the revoke SP, and
its credential is absent from the deployment until gate 2 is completed.

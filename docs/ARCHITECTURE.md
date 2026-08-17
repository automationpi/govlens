# Azure GovLens - Architecture & Roadmap

*The cheapest governance/compliance visibility for small Azure orgs: collect
read-only signals, store per-run snapshots, and show **trends over time** and
**config drift**: the thing the free tooling ecosystem doesn't give you.*

---

## 1. The thesis

Small orgs can't justify a CSPM suite. But the raw signals - Azure Policy
compliance, RBAC, Entra Conditional Access, identity security posture - are all
readable for free. What's missing is a place to **keep them over time** and see
**what changed**. GovLens is that place: a tiny Go app + Postgres that ingests
read-only governance data and renders trend + drift, with a JSON API and an MCP
server so both humans and AI can query it.

## 2. Tooling research (what exists, and the gap)

| Tool | License | What it is | We use it for |
|---|---|---|---|
| **AzGovViz** | free (MS community) | PowerShell; reads ARM (policy, RBAC, hierarchy) + Graph; renders a huge HTML report | policy compliance + RBAC |
| **EntraExporter** | MIT (Microsoft) | PowerShell; dumps Entra config to per-object JSON | Conditional Access |
| **Maester** | MIT (community) | PowerShell + Pester; ~700 curated security tests (CIS/CISA baselines) | security posture score |
| **ScubaGear** | public domain (CISA) | M365/Entra baseline conformance | (alternative to Maester) |
| **Senserva** | commercial | Dashboard over Maester JSON | - (this is the layer we build ourselves) |

**The gap none of them fill for free:** a self-hosted store + dashboard that
tracks **cross-domain (Azure + Entra) posture over time** and surfaces **drift**.
That's GovLens.

**Key realization (drives the roadmap):** AzGovViz and EntraExporter are, at
their core, just *authenticated REST clients*. Everything GovLens ingests from
them is a handful of ARM/Graph GETs. Maester is different - its value is the
**maintained ruleset**, not the fetching.

## 3. System architecture

```
COLLECT (read-only, in-tenant)         INGEST + STORE            SERVE
──────────────────────────────         ──────────────           ─────
[lean Go collector]  ──REST──┐
  ARM  roleAssignments        │
  ARM  policyStates/summarize ├─► store (Postgres) ──┬── HTML dashboard  (cmd/web)
  Graph conditionalAccess     │     runs / metrics   ├── JSON API        (/api/*)
                              │     findings / assign ├── MCP server      (cmd/mcp)
[optional: Maester] ──JSON────┘     (provenance)      └──
```

- **The app never mutates Azure.** Read-only SP for collection; the app touches
  only Postgres.
- **One query layer (`internal/store`)** backs all three surfaces - dashboard,
  API, MCP - so there is no logic duplication.

### Data model (`internal/store/schema.sql`)

- `runs` - one row per collection. **`tenant` is the Entra tenant id** (stable
  identity) and **`tenant_display`** is the human name (e.g. "Example Org");
  keyed by id so one Azure directory can never fork into multiple labels. Also
  `collected_at` and **`sources[]`** (which collectors contributed → provenance).
- `metrics` - flexible time-series (`domain/category/key → value`) for trends.
- `findings` - per-control results (policy compliance rows, Maester tests).
- `assignments` - RBAC + CA captured as state each run, for **drift** diffing.

### Notable design decisions

- **Provenance-guarded drift.** Drift diffs the two latest runs by `(kind,
  ident)`, but *only* for a kind whose source collector ran in **both** runs. A
  missing collector never reads as a false mass-removal - it surfaces as a
  suppressed banner. (Verified live: an EntraExporter-only run correctly hid
  RBAC drift instead of "removing" 15 real assignments.)
- **Transactional load** (`ReplaceRun`) via `CopyFrom` - a run lands whole or
  not at all.
- **Format-tolerant parsers.** Column/field names matched by candidate lists;
  discovery guards (e.g. only treat a CSV as compliance data if it has
  compliance columns).

## 4. The lean-collector pivot

Running the PowerShell tools end-to-end surfaced real overhead:

- AzGovViz needed a module install (**AzAPICall**), prompted on missing modules
  and **looped ~300M log lines** headless; ran **10×~500MB runspaces** (OOM on a
  WSL box); and hit a **fatal deprecated-API 404** (`classicAdministrators`).
- Maester's full 730-test suite needs **~40+ Graph scopes** (device management,
  threat hunting, SharePoint, Exchange/Teams/Intune); our governance-core 17
  leaves most tests `NotRun`.
- EntraExporter nests each object in its own subfolder; Maester serializes
  `CurrentVersion` as an **object**: both broke fixture-based parsers until
  caught against real output.

**Decision:** replace the AzGovViz + EntraExporter *collection* with a
**dependency-free Go collector** (`cmd/collect`, `internal/collect`) that:

- authenticates as the read-only SP via a **certificate client-assertion**
  (hand-rolled RS256 JWT, stdlib only - no MSAL, no PowerShell);
- pulls **ARM** `roleAssignments` (+ role-name resolution) and
  `policyStates/latest/summarize` across all readable subscriptions;
- pulls **Graph** `conditionalAccess/policies` (+ batched principal-name
  resolution via `directoryObjects/getByIds`);
- pulls **Graph** `roleManagement/directory/roleAssignments` - **Entra directory
  roles** (Global Administrator, User Administrator, …) held by users, groups, and
  service principals, for a **privileged-access review**: resolves principal
  name + type, flags service principals holding privileged roles, and runs a
  **Global-Administrator count** compliance check (Microsoft recommends 2-4).
  Directory-role changes are drift-tracked (`entra_role` kind), so a *new admin*
  is caught between runs;
- writes a `store.RunData` **directly to Postgres**: no files, no CSV, no
  native-discovery adapter.

This deletes the entire PowerShell supply chain for collection while keeping
**everything downstream unchanged** (schema, drift guard, dashboard, API, MCP).

**What we did NOT rebuild:** Maester's ruleset. Fetching is commodity; ~700
maintained security tests are a product. Options kept open: (a) run Maester as
an *optional* collector for the security score, or (b) author a small curated
set of Go rules over already-collected data.

## 5. Read-only identity

One app registration + SP (`govlens-collector`), secret-less by preference:

- **ARM:** `Reader` at the management-group root (covers all subscriptions).
- **Graph:** 17 read-only application permissions (Directory/Policy/RBAC/CA/
  auth-methods/reports/audit/risk/security/...).
- **Credential:** certificate now; **federated (OIDC)** for CI.

Setup gotcha (fixed in `scripts/create-readonly-sp.sh`): `az ad app permission
add` + `admin-consent` silently no-op until `requiredResourceAccess` is set via
`az ad app update`; app-permission propagation to tokens takes a few minutes.

## 6. Lessons learned

- Validate parsers against **real** tool output early - fixtures hid three bugs
  (nested CA dirs, version-as-object, real RBAC column names).
- Provenance beats "0 rows = deleted" for drift correctness.
- App-only Graph access needs **application permissions**, not directory roles
  (Global Reader doesn't grant app-only API access).
- **Identify a tenant by its Entra tenant id, never a free-text label.** An early
  mistake used `tenant` as a hand-typed label, which let the *same* real directory
  fragment across several "tenants" (and sit next to synthetic demo data). Fixed:
  the collector keys by the SP's tenant id and auto-derives the display name from
  Graph `/organization`. One directory ⇒ one tenant ⇒ one timeline.
- **RBAC + Conditional Access are fully readable with `Reader` + the Graph read
  perms**: the lean collector pulled **307 RBAC assignments across 5 subs + CA
  in ~25s**, resolving real principal names via Graph `getByIds` (with graceful
  GUID fallback for stale principals).
- **Azure Policy compliance is the exception:** `policyStates/latest/summarize`
  is a PolicyInsights **`/action`**, not a `/read`, so `Reader` returns 403 and
  *no read-only built-in role grants it* (only Contributor-level roles do).
  Solved with a minimal read-only **custom role**: `GovLens Policy Reader`
  (`Microsoft.PolicyInsights/policyStates/summarize/action` + `queryResults/action`
  + `policyAssignments|policyDefinitions|policySetDefinitions/read`) - created and
  assigned to the SP at the MG root by `scripts/create-readonly-sp.sh`. **Confirmed
  working**: real compliance 15.3% (Defender `securitycenterbuiltin` initiative).
- **Namespace gotcha (cost an hour of "propagation" red herring):** the summarize
  endpoint must be called via the **`Microsoft.PolicyInsights`** provider path,
  which checks `Microsoft.PolicyInsights/policyStates/summarize/action`. The
  `Microsoft.Authorization/policyStates` path checks a *different* action
  (`Microsoft.Authorization/policyStates/summarize/action`) that no read role -
  built-in or custom - grants. Right role + wrong URL = a 403 that looks exactly
  like slow RBAC propagation. Always read the *exact denied action* in the 403.

## 7. Roadmap

**Now / next**
- [x] Read-only **custom role** (`GovLens Policy Reader`) for PolicyInsights
      summarize, created + assigned to the SP (see §6). Fills the policy tile once
      the MG→sub RBAC assignment propagates.
- [x] Harden the lean collector: **429/5xx retry with backoff** (Retry-After
      aware) + request timeout; **MG-scoped** subscription discovery (`-mg`, via
      the descendants API); optional **PII pseudonymization** (`-pseudonymize`,
      stable SHA-256 hashes instead of Graph name resolution).
- [ ] Rename source keys to be tool-agnostic (`azure-rbac`/`entra-ca` rather than
      `azgovviz-rbac`/`entraexporter-ca`) now that collection is Go-native.
- [ ] Decide Maester: optional collector vs. a curated Go rule set (~a dozen
      high-value checks over collected data).
- [ ] 15-day **schedule**: run `collect` on a cron with the SP's **federated**
      credential (Azure DevOps / GitHub Actions).

**Remediation workflow (privilege separation)**
- [x] **Revoke-request queue + 2-stage review.** The UI "Mark for revoke" on an
      assignment writes only to GovLens's own `revoke_requests` table (no Azure
      permission, revokes nothing). State machine: `pending → approved | rejected`
      (human review) then, later, `approved → processing → done|failed|skipped`
      (worker). Idempotent marking, per-target open-request guard, full audit
      fields (requested/decided by + notes + timestamps). Review page + pending
      count in the header.
- [x] **Authentication (extensible) + role-based authorization.** Pluggable
      `auth.Provider` - any **OIDC** issuer (Entra ID, Google, Okta…) via go-oidc,
      or a local **dev** provider; signed-cookie sessions; middleware requires
      login for all non-public routes. Roles (`admin`, `approver`) in `app_users`,
      granted from an **admin page**; bootstrap admins via `GOVLENS_ADMIN_EMAILS`.
      Enforcement: mark = any signed-in user (identity stamped as `requested_by`);
      approve/reject = **approver**; admin page = **admin**. Config: `GOVLENS_AUTH`
      = `off|entra|oidc|dev`. For Entra: `GOVLENS_ENTRA_TENANT` + `OIDC_CLIENT_ID`
      / `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URL` (a web app registration with the
      redirect URI; `openid email profile` scopes). Auth `off` (default) keeps
      local use open.
- [ ] **Still deferred - the worker.** A *separate* binary with a *separate*,
      write-capable `govlens-remediator` SP (`RoleManagement.ReadWrite.Directory`
      / scoped UAA), running isolated, that only touches `approved` rows and
      enforces safety rules (never remove the last Global Admin / break-glass;
      revocable-role allowlist; rate limit; re-validate before delete). A queue
      relocates *where* the write happens, not *who* may trigger it - the approval
      gate + auth (now in place) are the load-bearing safety, not the queue.

**Remediation guardrails (admin-configurable)**
- [x] **Non-revocable roles** (`protected_roles`) - a role here can never be revoked
      (Revoke hidden, mark 403, worker skips). Global Administrator protected by default.
- [x] **Per-principal-type policy** (`type_policies`, global admin only): each of
      User / Group / ServicePrincipal can be **blocked** (never revocable - e.g. disable
      deleting Groups/SPs) or **global** (revocation requires a *global* approver, not a
      subscription-scoped one - e.g. Group deletions need top-level sign-off). Enforced
      in the UI, mark endpoint, approval, and worker.

**Subscription-scoped RBAC**
- [x] **Subscriptions registry** (collector records id+name) + a **subscription
      selector** on the run-detail that scopes RBAC + findings to one subscription.
- [x] **Scoped role model**: grants are `(email, scope, role)` where scope is `*`
      (tenant-wide) or a subscription id (`user_scope_roles`). **Scope-aware
      approval**: to approve a revoke request you need a global approver/admin or an
      approver/admin of that request's subscription (Entra directory-role requests
      require global). **Subscription admins** grant approvers within their own
      subscription (team self-service) via the admin page's scope dropdown; global
      admins manage everything. Verified: a Production approver can act on a
      Production request; a Test approver gets 403.

**Then**
- [x] Multi-tenant FE: **tenant switcher** (one instance serves all tenants via
      `?tenant=`) + **runs history** + **per-run detail** pages (findings + RBAC
      with principal-type badges + CA). Server-rendered over the store; the JSON
      API remains for external consumers. Shared `styles` template across pages.
      (Surfaced + fixed a real metric bug: inherited MG-scoped RBAC assignments
      repeat per subscription - the count now dedupes by assignment id.)
- [ ] Web-app auth (Entra ID in front of the dashboard/API).
- [ ] DB backup of the mounted disk; drift alerting (webhook/Slack).
- [ ] Map controls to frameworks (CIS/SCuBA) for compliance reporting.

**Component map**
```
cmd/collect   lean SP→ARM/Graph→Postgres collector   (new; replaces PS collection)
cmd/ingest    file-based ingest (fixtures + native adapter, still supported)
cmd/web       dashboard + JSON API
cmd/mcp       MCP server (5 tools)
internal/collect  auth (cert JWT) + ARM + Graph clients
internal/ingest   parsers + native discovery (kept for file-based sources)
internal/store    schema + queries (the one query layer)
internal/web      dashboard handlers + API
scripts/          create-readonly-sp.sh, bootstrap-modules.ps1, connect-sp.ps1
collect.ps1       PowerShell collector (kept for Maester; AzGovViz optional)
```

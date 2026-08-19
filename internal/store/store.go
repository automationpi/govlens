// Package store owns the Postgres connection, schema, and all queries.
package store

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

//go:embed reset.sql
var resetSQL string

// Reset drops all GovLens-owned tables (only ours, so a shared Postgres keeps its
// other tables). Used for database.init="fresh"; the caller re-applies the schema
// afterwards via Open. This DESTROYS all GovLens data, so it is opt-in only.
func Reset(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, resetSQL); err != nil {
		return fmt.Errorf("reset schema: %w", err)
	}
	return nil
}

type Store struct{ Pool *pgxpool.Pool }

// Open connects (with a short retry loop so it survives Postgres still booting
// in docker-compose) and applies the schema.
func Open(ctx context.Context, dsn string) (*Store, error) {
	var pool *pgxpool.Pool
	var err error
	for i := 0; i < 30; i++ {
		pool, err = pgxpool.New(ctx, dsn)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				break
			}
			pool.Close()
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() { s.Pool.Close() }

// Source keys identify which collector produced data in a run (provenance).
const (
	SrcPolicy     = "azgovviz-policy"
	SrcRBAC       = "azgovviz-rbac"
	SrcMaester    = "maester"
	SrcCA         = "entraexporter-ca"
	SrcEntraRoles = "entra-roles"
)

// kindSource maps an assignment kind to the collector source that produces it,
// so drift can tell "genuinely gone" from "not collected this run".
var kindSource = map[string]string{"rbac": SrcRBAC, "ca_policy": SrcCA, "entra_role": SrcEntraRoles}

// RunData is one fully-parsed collection run, ready to load atomically.
type RunData struct {
	Tenant        string // stable identity — the Entra tenant id
	TenantDisplay string // human name shown in the UI (e.g. "Example Org")
	CollectedAt   time.Time
	Label         string
	Sources       []string // which collectors contributed (see Src* constants)
	Subscriptions  []Subscription
	ResourceGroups []ResourceGroup // resource groups under the collected subscriptions
	Metrics        []Metric
	Findings       []Finding
	Assignments    []Assignment
	Catalog        []CatalogRole       // grantable role definitions discovered this run (tenant-scoped upsert)
	Activity       []PrincipalActivity // last sign-in per principal for dormancy (roadmap #2)
}

// PrincipalActivity is a principal's last observed sign-in, for dormancy analysis.
// LastSignIn is zero when never seen or when sign-in data is unavailable.
type PrincipalActivity struct {
	OID        string
	LastSignIn time.Time
}

// ResourceGroup is one resource group under a subscription (for request scoping).
type ResourceGroup struct {
	SubID, Name string
}

// ReplaceRun loads a run in a single transaction: upsert the run row, clear any
// prior child rows for it, then bulk-insert via CopyFrom. Either the whole run
// lands or none of it does, so a mid-load crash can't leave a half-ingested run.
func (s *Store) ReplaceRun(ctx context.Context, rd RunData) (int64, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) // no-op after a successful Commit

	if rd.Sources == nil {
		rd.Sources = []string{}
	}
	var id int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO runs (tenant, collected_at, source_label, sources, tenant_display)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (tenant, collected_at)
		DO UPDATE SET source_label = EXCLUDED.source_label, sources = EXCLUDED.sources,
		             tenant_display = EXCLUDED.tenant_display
		RETURNING id`, rd.Tenant, rd.CollectedAt, rd.Label, rd.Sources, rd.TenantDisplay).Scan(&id); err != nil {
		return 0, err
	}
	for _, t := range []string{"metrics", "findings", "assignments"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+t+" WHERE run_id=$1", id); err != nil {
			return 0, err
		}
	}

	metricRows := make([][]any, 0, len(rd.Metrics))
	for _, m := range rd.Metrics {
		metricRows = append(metricRows, []any{id, m.Domain, m.Category, m.Key, m.Value})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"metrics"},
		[]string{"run_id", "domain", "category", "key", "value"},
		pgx.CopyFromRows(metricRows)); err != nil {
		return 0, fmt.Errorf("copy metrics: %w", err)
	}

	findingRows := make([][]any, 0, len(rd.Findings))
	for _, f := range rd.Findings {
		findingRows = append(findingRows, []any{id, f.Domain, f.Source, f.ControlID,
			f.Title, f.Severity, f.Status, f.Category, f.Scope, f.HelpURL})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"findings"},
		[]string{"run_id", "domain", "source", "control_id", "title", "severity", "status", "category", "scope", "help_url"},
		pgx.CopyFromRows(findingRows)); err != nil {
		return 0, fmt.Errorf("copy findings: %w", err)
	}

	// Dedupe assignments by (kind, ident) so a duplicated row can't violate the PK.
	seen := map[string]bool{}
	assignRows := make([][]any, 0, len(rd.Assignments))
	for _, a := range rd.Assignments {
		k := a.Kind + "\x00" + a.Ident
		if a.Ident == "" || seen[k] {
			continue
		}
		seen[k] = true
		var createdOn any
		if !a.CreatedOn.IsZero() {
			createdOn = a.CreatedOn
		}
		assignRows = append(assignRows, []any{id, a.Domain, a.Kind, a.Ident,
			a.Principal, a.PrincipalType, a.Role, a.Scope, a.Display,
			createdOn, a.CreatedBy, a.CreatedByName})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"assignments"},
		[]string{"run_id", "domain", "kind", "ident", "principal", "principal_type", "role", "scope", "display",
			"created_on", "created_by", "created_by_name"},
		pgx.CopyFromRows(assignRows)); err != nil {
		return 0, fmt.Errorf("copy assignments: %w", err)
	}

	// Upsert principal activity (tenant-scoped) for dormancy analysis.
	for _, pa := range rd.Activity {
		if pa.OID == "" {
			continue
		}
		var last any
		if !pa.LastSignIn.IsZero() {
			last = pa.LastSignIn
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO principal_activity (tenant, oid, last_sign_in, updated_at)
			VALUES ($1,$2,$3,now())
			ON CONFLICT (tenant, oid) DO UPDATE SET last_sign_in=EXCLUDED.last_sign_in, updated_at=now()`,
			rd.Tenant, pa.OID, last); err != nil {
			return 0, fmt.Errorf("upsert activity: %w", err)
		}
	}

	for _, sub := range rd.Subscriptions {
		if _, err := tx.Exec(ctx, `
			INSERT INTO subscriptions (tenant, sub_id, name) VALUES ($1,$2,$3)
			ON CONFLICT (tenant, sub_id) DO UPDATE SET name = EXCLUDED.name`,
			rd.Tenant, sub.ID, sub.Name); err != nil {
			return 0, err
		}
	}

	// Refresh resource groups for the subscriptions this run covered (delete + insert
	// so removed RGs disappear from the picker; other subs' RGs are left untouched).
	if len(rd.Subscriptions) > 0 {
		subIDs := make([]string, 0, len(rd.Subscriptions))
		for _, s := range rd.Subscriptions {
			subIDs = append(subIDs, s.ID)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM resource_groups WHERE tenant=$1 AND sub_id = ANY($2)`,
			rd.Tenant, subIDs); err != nil {
			return 0, err
		}
		for _, rg := range rd.ResourceGroups {
			if _, err := tx.Exec(ctx, `
				INSERT INTO resource_groups (tenant, sub_id, name) VALUES ($1,$2,$3)
				ON CONFLICT DO NOTHING`, rd.Tenant, rg.SubID, rg.Name); err != nil {
				return 0, err
			}
		}
	}

	// Role catalog is tenant-scoped (not per-run): upsert, refreshing tier + last_seen.
	// Roles that disappear upstream are left in place (retirement is handled separately),
	// so existing grants are never orphaned by a transient collection gap.
	for _, cr := range rd.Catalog {
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_catalog
			  (tenant, role_def_id, role_name, role_kind, is_custom, deprecated, tier, tier_reason)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (tenant, role_def_id) DO UPDATE SET
			  role_name=EXCLUDED.role_name, role_kind=EXCLUDED.role_kind, is_custom=EXCLUDED.is_custom,
			  deprecated=EXCLUDED.deprecated, tier=EXCLUDED.tier, tier_reason=EXCLUDED.tier_reason,
			  last_seen=now()`,
			rd.Tenant, cr.RoleDefID, cr.RoleName, cr.RoleKind, cr.IsCustom, cr.Deprecated, cr.Tier, cr.TierReason); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return id, nil
}

type Metric struct {
	Domain, Category, Key string
	Value                 float64
}

type Finding struct {
	Domain, Source, ControlID, Title, Severity, Status, Category, Scope, HelpURL string
}

type Assignment struct {
	Domain, Kind, Ident, Principal, PrincipalType, Role, Scope, Display string
	// Change attribution (RBAC only, from the assignment's ARM properties): when the
	// assignment was created and by whom. CreatedBy is an object id; CreatedByName is
	// the resolved display name, left empty when the creator does not resolve (deleted,
	// external, or unreadable) which is itself a signal.
	CreatedOn     time.Time
	CreatedBy     string
	CreatedByName string
}

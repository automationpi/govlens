package store

import (
	"context"
	"time"
)

type Run struct {
	ID          int64
	Tenant      string // Entra tenant id (stable identity)
	Display     string // human tenant name
	CollectedAt time.Time
	Label       string
	Sources     []string
}

// TenantInfo pairs a tenant's stable id with its display name for the switcher.
type TenantInfo struct {
	ID      string
	Display string
}

// TrendPoint is one run's headline numbers, oldest-first, for the trend chart.
type TrendPoint struct {
	Run           Run
	PolicyPct     float64 // compliant resources / total, 0..100 (-1 if no data)
	MaesterPct    float64 // passed tests / executed, 0..100 (-1 if no data)
	RBACCount     int
	CAEnabled     int
	CATotal       int
	FailedControl int // failed maester + non-compliant policy assignments
	DirRoles      int // Entra directory role assignments
	Privileged    int // of those, privileged admin roles
	GlobalAdmins  int
}

// Tenants lists distinct tenants (id + display name) that have at least one run,
// newest activity first.
func (s *Store) Tenants(ctx context.Context) ([]TenantInfo, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT tenant, COALESCE(NULLIF(max(tenant_display),''), tenant) AS display
		   FROM runs GROUP BY tenant ORDER BY max(collected_at) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantInfo
	for rows.Next() {
		var t TenantInfo
		if err := rows.Scan(&t.ID, &t.Display); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Runs(ctx context.Context, tenant string) ([]Run, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, tenant, COALESCE(tenant_display,''), collected_at, COALESCE(source_label,''), sources
		   FROM runs WHERE tenant=$1 ORDER BY collected_at`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.Tenant, &r.Display, &r.CollectedAt, &r.Label, &r.Sources); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RunByID fetches a single run (used by the run-detail page).
func (s *Store) RunByID(ctx context.Context, id int64) (Run, error) {
	var r Run
	err := s.Pool.QueryRow(ctx,
		`SELECT id, tenant, COALESCE(tenant_display,''), collected_at, COALESCE(source_label,''), sources
		   FROM runs WHERE id=$1`, id).
		Scan(&r.ID, &r.Tenant, &r.Display, &r.CollectedAt, &r.Label, &r.Sources)
	return r, err
}

type AssignmentRow struct {
	Ident, Kind, Principal, PrincipalType, Role, Scope, Display string
}

// assignmentFilter is the shared WHERE for the assignment queries: by kind,
// principal type, a free-text search, and an optional subscription id ($5).
const assignmentFilter = `run_id=$1 AND ($2='' OR kind=$2)
	AND ($3='' OR principal_type=$3)
	AND ($4='' OR principal ILIKE '%'||$4||'%' OR role ILIKE '%'||$4||'%' OR scope ILIKE '%'||$4||'%')
	AND ($5='' OR scope ILIKE '%'||$5||'%')`

// RunAssignments returns a run's assignments, filtered by kind, principal type,
// free-text search, and subscription id. Empty filter args match everything.
func (s *Store) RunAssignments(ctx context.Context, runID int64, kind, ptype, search, sub string, limit int) ([]AssignmentRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT ident, kind, COALESCE(principal,''), COALESCE(principal_type,''),
		       COALESCE(role,''), COALESCE(scope,''), COALESCE(display,'')
		  FROM assignments
		 WHERE `+assignmentFilter+`
		 ORDER BY kind, display, role
		 LIMIT $6`, runID, kind, ptype, search, sub, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssignmentRow
	for rows.Next() {
		var a AssignmentRow
		if err := rows.Scan(&a.Ident, &a.Kind, &a.Principal, &a.PrincipalType, &a.Role, &a.Scope, &a.Display); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AssignmentCount returns how many assignments of a kind a run has (unfiltered).
func (s *Store) AssignmentCount(ctx context.Context, runID int64, kind string) int {
	var n int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM assignments WHERE run_id=$1 AND kind=$2`, runID, kind).Scan(&n)
	return n
}

// AssignmentMatchCount returns how many assignments match the given filters.
func (s *Store) AssignmentMatchCount(ctx context.Context, runID int64, kind, ptype, search, sub string) int {
	var n int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM assignments WHERE `+assignmentFilter,
		runID, kind, ptype, search, sub).Scan(&n)
	return n
}

func hasSource(r Run, src string) bool {
	for _, s := range r.Sources {
		if s == src {
			return true
		}
	}
	return false
}

func metricVal(ctx context.Context, s *Store, runID int64, cat, key string) float64 {
	var v float64
	err := s.Pool.QueryRow(ctx,
		`SELECT value FROM metrics WHERE run_id=$1 AND category=$2 AND key=$3`,
		runID, cat, key).Scan(&v)
	if err != nil {
		return 0
	}
	return v
}

// Trend builds one TrendPoint per run (oldest first).
func (s *Store) Trend(ctx context.Context, tenant string) ([]TrendPoint, error) {
	runs, err := s.Runs(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var out []TrendPoint
	for _, r := range runs {
		tp := TrendPoint{Run: r, PolicyPct: -1, MaesterPct: -1}

		comp := metricVal(ctx, s, r.ID, "policy_compliance", "compliant_resources")
		noncomp := metricVal(ctx, s, r.ID, "policy_compliance", "noncompliant_resources")
		if comp+noncomp > 0 {
			tp.PolicyPct = 100 * comp / (comp + noncomp)
		}

		passed := metricVal(ctx, s, r.ID, "maester", "passed")
		failed := metricVal(ctx, s, r.ID, "maester", "failed")
		if passed+failed > 0 {
			tp.MaesterPct = 100 * passed / (passed + failed)
		}

		tp.RBACCount = int(metricVal(ctx, s, r.ID, "rbac", "count"))
		tp.CAEnabled = int(metricVal(ctx, s, r.ID, "ca_policy", "enabled"))
		tp.CATotal = int(metricVal(ctx, s, r.ID, "ca_policy", "total"))
		tp.FailedControl = int(failed + metricVal(ctx, s, r.ID, "policy_compliance", "noncompliant_assignments"))
		tp.DirRoles = int(metricVal(ctx, s, r.ID, "entra_role", "total"))
		tp.Privileged = int(metricVal(ctx, s, r.ID, "entra_role", "privileged"))
		tp.GlobalAdmins = int(metricVal(ctx, s, r.ID, "entra_role", "global_admins"))
		out = append(out, tp)
	}
	return out, nil
}

type FindingRow struct {
	Domain, Source, ControlID, Title, Severity, Status, Category, Scope, HelpURL string
}

// FailingFindings returns non-passing controls for a run (optionally scoped to a
// subscription id), most severe first.
func (s *Store) FailingFindings(ctx context.Context, runID int64, sub string, limit int) ([]FindingRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT domain, source, control_id, title, COALESCE(severity,''), status,
		       COALESCE(category,''), COALESCE(scope,''), COALESCE(help_url,'')
		  FROM findings
		 WHERE run_id=$1 AND status IN ('failed','non_compliant')
		   AND ($2='' OR scope ILIKE '%'||$2||'%')
		 ORDER BY CASE COALESCE(severity,'')
		            WHEN 'High' THEN 0 WHEN 'Medium' THEN 1
		            WHEN 'Low' THEN 2 ELSE 3 END, title
		 LIMIT $3`, runID, sub, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		if err := rows.Scan(&f.Domain, &f.Source, &f.ControlID, &f.Title, &f.Severity,
			&f.Status, &f.Category, &f.Scope, &f.HelpURL); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

type DriftRow struct {
	Kind    string // rbac | ca_policy
	Change  string // added | removed | changed
	Display string
	Detail  string // role @ scope, or old->new state
}

// Suppressed names a kind whose drift was withheld because a collector didn't
// run in one of the two runs (so a diff would be a false mass add/removal).
type Suppressed struct {
	Kind   string
	Reason string
}

// Drift diffs the two most recent runs by (kind, ident), but ONLY for kinds
// whose source collector ran in BOTH runs. A kind missing from either run is
// reported as suppressed instead of producing phantom removals.
func (s *Store) Drift(ctx context.Context, tenant string) (newer, older *Run, rows []DriftRow, suppressed []Suppressed, err error) {
	runs, err := s.Runs(ctx, tenant)
	if err != nil || len(runs) < 2 {
		return nil, nil, nil, nil, err
	}
	n, o := runs[len(runs)-1], runs[len(runs)-2]

	// Decide which kinds are safe to diff based on collection provenance.
	var allowed []string
	for kind, src := range kindSource {
		switch {
		case !hasSource(n, src):
			suppressed = append(suppressed, Suppressed{Kind: kind, Reason: "not collected in latest run"})
		case !hasSource(o, src):
			suppressed = append(suppressed, Suppressed{Kind: kind, Reason: "not collected in previous run"})
		default:
			allowed = append(allowed, kind)
		}
	}
	if len(allowed) == 0 {
		return &n, &o, nil, suppressed, nil
	}

	q, err := s.Pool.Query(ctx, `
		SELECT COALESCE(n.kind,o.kind), n.ident, o.ident,
		       COALESCE(n.display,o.display),
		       COALESCE(n.role,''), COALESCE(o.role,''),
		       COALESCE(n.scope,o.scope,'')
		  FROM (SELECT * FROM assignments WHERE run_id=$1) n
		  FULL OUTER JOIN (SELECT * FROM assignments WHERE run_id=$2) o
		    ON n.kind=o.kind AND n.ident=o.ident
		 WHERE (n.ident IS NULL OR o.ident IS NULL OR n.role IS DISTINCT FROM o.role)
		   AND COALESCE(n.kind,o.kind) = ANY($3)
		 ORDER BY 1,4`, n.ID, o.ID, allowed)
	if err != nil {
		return &n, &o, nil, suppressed, err
	}
	defer q.Close()
	for q.Next() {
		var kind, nIdent, oIdent, display, nRole, oRole, scope *string
		if err := q.Scan(&kind, &nIdent, &oIdent, &display, &nRole, &oRole, &scope); err != nil {
			return &n, &o, nil, suppressed, err
		}
		dr := DriftRow{Kind: deref(kind), Display: deref(display)}
		switch {
		case nIdent == nil:
			dr.Change = "removed"
			dr.Detail = detail(deref(oRole), deref(scope))
		case oIdent == nil:
			dr.Change = "added"
			dr.Detail = detail(deref(nRole), deref(scope))
		default:
			dr.Change = "changed"
			dr.Detail = deref(oRole) + " → " + deref(nRole)
		}
		rows = append(rows, dr)
	}
	return &n, &o, rows, suppressed, q.Err()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func detail(role, scope string) string {
	if scope == "" {
		return role
	}
	return role + " @ " + scope
}

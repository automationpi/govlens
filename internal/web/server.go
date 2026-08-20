// Package web serves the governance dashboard from the store.
package web

import (
	"context"
	"embed"
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

//go:embed templates/*.html
var tmplFS embed.FS

// faviconSVG is the GovLens tab mark: a magnifier lens with a compliance check,
// on the brand accent. Single flat SVG so it stays crisp at 16px.
const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">` +
	`<rect width="32" height="32" rx="7" fill="#2d6cdf"/>` +
	`<circle cx="14" cy="14" r="6.5" fill="none" stroke="#fff" stroke-width="2.4"/>` +
	`<path d="M10.6 14.2l2.5 2.5 4.4-4.9" fill="none" stroke="#fff" stroke-width="2.2" ` +
	`stroke-linecap="round" stroke-linejoin="round"/>` +
	`<path d="M18.7 18.7l5 5" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/></svg>`

type Server struct {
	store  *store.Store
	tenant string
	auth   *auth.Auth
	tmpl   *template.Template
}

func New(s *store.Store, tenant string, a *auth.Auth) (*Server, error) {
	t, err := template.New("").Funcs(template.FuncMap{
		"date":     func(t time.Time) string { return t.Format("Jan 02") },
		"datetime": func(t time.Time) string { return t.Format("Jan 02, 15:04 MST") },
		"pct": func(f float64) string {
			if f < 0 {
				return "—"
			}
			return fmt.Sprintf("%.1f%%", f)
		},
		"sub": func(a, b float64) float64 { return a - b },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		// prevVal pulls a headline % off the previous run for delta display.
		"prevVal": func(prev *store.TrendPoint, which string) float64 {
			if prev == nil {
				return -1
			}
			if which == "maester" {
				return prev.MaesterPct
			}
			return prev.PolicyPct
		},
		"gridlines": gridlines,
		"priv":      func(role string) bool { return privilegedDirRolesWeb[role] },
		"types":     func() []string { return []string{"User", "Group", "ServicePrincipal"} },
		"handle":    handleOf,
	}).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{store: s, tenant: tenant, auth: a, tmpl: t}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fmt.Fprint(w, faviconSVG)
	})
	s.authRoutes(mux)
	s.adminRoutes(mux)
	s.apiRoutes(mux)
	s.revokeRoutes(mux)
	s.grantRoutes(mux)
	s.driftRoutes(mux)
	mux.HandleFunc("/run", s.runDetail)
	mux.HandleFunc("/run/latest", s.runLatest)
	mux.HandleFunc("/runs", s.runsPage)
	mux.HandleFunc("/", s.dashboard)
	return s.authMiddleware(mux)
}

// chartPoint carries precomputed SVG coordinates so the template stays logic-free.
type chartPoint struct {
	X, Y  float64
	Label string
	Val   float64
	Has   bool
}

// lineSeries is a fully precomputed SVG line: a "points" string for the
// <polyline> plus the individual dots (for hover titles).
type lineSeries struct {
	Points string
	Dots   []chartPoint
}

type dashboardData struct {
	User           *auth.User
	Tenant         string
	TenantDisplay  string
	Tenants        []store.TenantInfo
	PendingRevokes int
	Runs           int
	RunList        []store.Run
	Latest       *store.TrendPoint
	Prev         *store.TrendPoint
	Trend        []store.TrendPoint
	PolicyLine   lineSeries
	MaesterLine  lineSeries
	Drift        []store.DriftRow
	DriftNewer   *store.Run
	DriftOlder   *store.Run
	AddedCount   int
	RemovedCount int
	Suppressed   []store.Suppressed
	Findings     []store.FindingRow
}

// resolveTenant picks the requested tenant id, else the first available, else
// the server default.
func (s *Server) resolveTenant(r *http.Request, tenants []store.TenantInfo) string {
	if t := r.URL.Query().Get("tenant"); t != "" {
		return t
	}
	if len(tenants) > 0 {
		return tenants[0].ID
	}
	return s.tenant
}

// displayFor returns a tenant's display name (falling back to the id).
func displayFor(tenants []store.TenantInfo, id string) string {
	for _, t := range tenants {
		if t.ID == id {
			return t.Display
		}
	}
	return id
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tenant := s.resolveTenant(r, tenants)

	trend, err := s.store.Trend(ctx, tenant)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	d := dashboardData{User: userOf(r), Tenant: tenant, TenantDisplay: displayFor(tenants, tenant),
		Tenants: tenants, PendingRevokes: s.store.PendingRevokeCount(ctx, tenant),
		Runs: len(trend), Trend: trend}
	if len(trend) == 0 {
		s.render(w, "dashboard.html", d)
		return
	}
	d.Latest = &trend[len(trend)-1]
	if len(trend) >= 2 {
		d.Prev = &trend[len(trend)-2]
	}
	d.PolicyLine = buildLine(trend, func(t store.TrendPoint) float64 { return t.PolicyPct })
	d.MaesterLine = buildLine(trend, func(t store.TrendPoint) float64 { return t.MaesterPct })

	// Runs: the dashboard shows only the latest two (newest first); the full,
	// paginated history lives at /runs.
	for i := len(trend) - 1; i >= 0 && len(d.RunList) < 2; i-- {
		d.RunList = append(d.RunList, trend[i].Run)
	}

	newer, older, drift, suppressed, err := s.store.Drift(ctx, tenant)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	d.DriftNewer, d.DriftOlder, d.Drift, d.Suppressed = newer, older, drift, suppressed
	for _, dr := range drift {
		switch dr.Change {
		case "added":
			d.AddedCount++
		case "removed":
			d.RemovedCount++
		}
	}
	if fr, err := s.store.FailingFindings(ctx, d.Latest.Run.ID, "", 25); err == nil {
		d.Findings = fr
	}
	s.render(w, "dashboard.html", d)
}

type runDetailData struct {
	User        *auth.User
	Run         store.Run
	Point       *store.TrendPoint
	Findings    []store.FindingRow
	RBAC        []store.AssignmentRow
	CA          []store.AssignmentRow
	DirRoles    []store.AssignmentRow
	RBACAll     int // total RBAC in the run (unfiltered)
	RBACMatched int // matching the active filter
	RBACType    string
	RBACQuery   string
	CAAll       int
	DirRoleAll  int
	RBACCap       int
	RBACPage      int // 1-based page for the RBAC table
	RBACPages     int // total pages given the active filter
	RBACFirstRow  int // 1-based index of the first row on this page
	RBACLastRow   int // 1-based index of the last row on this page
	RBACHasPrev   bool
	RBACHasNext   bool
	RBACPrevPage  int
	RBACNextPage  int
	Marked        map[string]string // target ident -> open request status
	Protected     map[string]bool   // role name -> non-revocable
	Blocked       map[string]bool   // principal type -> non-revocable
	Subscriptions []store.Subscription
	Sub           string // selected subscription filter (id), "" = all
}

func (s *Server) runDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := parseInt64(r.URL.Query().Get("run"))
	if id == 0 {
		http.Error(w, "missing ?run=<id>", 400)
		return
	}
	run, err := s.store.RunByID(ctx, id)
	if err != nil {
		http.Error(w, "run not found", 404)
		return
	}
	d := runDetailData{User: userOf(r), Run: run, RBACCap: 200}

	// Reuse the per-run headline numbers from the tenant's trend.
	if trend, err := s.store.Trend(ctx, run.Tenant); err == nil {
		for i := range trend {
			if trend[i].Run.ID == id {
				d.Point = &trend[i]
			}
		}
	}
	// Subscription filter (page-level) scopes RBAC + findings to one subscription.
	d.Sub = r.URL.Query().Get("sub")
	d.Subscriptions, _ = s.store.Subscriptions(ctx, run.Tenant)

	if fr, err := s.store.FailingFindings(ctx, id, d.Sub, 200); err == nil {
		d.Findings = fr
	}
	// RBAC filters (server-side, so they search all assignments, not just the page).
	d.RBACType = r.URL.Query().Get("rbac_type")
	d.RBACQuery = strings.TrimSpace(r.URL.Query().Get("rbac_q"))
	d.RBACAll = s.store.AssignmentCount(ctx, id, "rbac")
	d.RBACMatched = s.store.AssignmentMatchCount(ctx, id, "rbac", d.RBACType, d.RBACQuery, d.Sub)

	// Paginate the RBAC table. Total rows depends on whether a filter is active.
	rbacTotal := d.RBACAll
	if d.RBACType != "" || d.RBACQuery != "" || d.Sub != "" {
		rbacTotal = d.RBACMatched
	}
	d.RBACPage = 1
	if p, err := strconv.Atoi(r.URL.Query().Get("rbac_page")); err == nil && p > 1 {
		d.RBACPage = p
	}
	d.RBACPages = (rbacTotal + d.RBACCap - 1) / d.RBACCap
	if d.RBACPages < 1 {
		d.RBACPages = 1
	}
	if d.RBACPage > d.RBACPages {
		d.RBACPage = d.RBACPages
	}
	offset := (d.RBACPage - 1) * d.RBACCap
	d.RBAC, _ = s.store.RunAssignments(ctx, id, "rbac", d.RBACType, d.RBACQuery, d.Sub, d.RBACCap, offset)
	if len(d.RBAC) > 0 {
		d.RBACFirstRow = offset + 1
		d.RBACLastRow = offset + len(d.RBAC)
	}
	d.RBACHasPrev, d.RBACPrevPage = d.RBACPage > 1, d.RBACPage-1
	d.RBACHasNext, d.RBACNextPage = d.RBACPage < d.RBACPages, d.RBACPage+1

	d.CA, _ = s.store.RunAssignments(ctx, id, "ca_policy", "", "", "", 200, 0)
	d.DirRoles, _ = s.store.RunAssignments(ctx, id, "entra_role", "", "", "", 500, 0)
	d.CAAll = s.store.AssignmentCount(ctx, id, "ca_policy")
	d.DirRoleAll = s.store.AssignmentCount(ctx, id, "entra_role")
	d.Marked, _ = s.store.OpenRevokeTargets(ctx, run.Tenant)
	d.Protected, _ = s.store.ProtectedRoleSet(ctx)
	d.Blocked = map[string]bool{}
	if tp, err := s.store.TypePolicies(ctx); err == nil {
		for t, p := range tp {
			if p == "blocked" {
				d.Blocked[t] = true
			}
		}
	}
	s.render(w, "run.html", d)
}

type runsData struct {
	User          *auth.User
	Tenant        string
	TenantDisplay string
	Tenants       []store.TenantInfo
	Runs          []store.Run
	Total         int
	Page          int
	FirstRow      int
	LastRow       int
	HasPrev       bool
	HasNext       bool
	PrevPage      int
	NextPage      int
}

// runLatest redirects to the newest run's detail page. Backs the "Manage access"
// nav link so it always lands on the current snapshot without knowing its id.
func (s *Server) runLatest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenants, _ := s.store.Tenants(ctx)
	tenant := s.resolveTenant(r, tenants)
	runs, err := s.store.Runs(ctx, tenant)
	if err != nil || len(runs) == 0 {
		http.Redirect(w, r, "/?tenant="+url.QueryEscape(tenant), http.StatusSeeOther)
		return
	}
	latest := runs[len(runs)-1] // Runs is ordered oldest..newest
	http.Redirect(w, r, "/run?run="+strconv.FormatInt(latest.ID, 10), http.StatusSeeOther)
}

// runsPage renders the full run history, newest first, paginated (20/page).
func (s *Server) runsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tenant := s.resolveTenant(r, tenants)
	runs, err := s.store.Runs(ctx, tenant)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rev := make([]store.Run, len(runs)) // newest first
	for i := range runs {
		rev[i] = runs[len(runs)-1-i]
	}
	const per = 20
	d := runsData{User: userOf(r), Tenant: tenant, TenantDisplay: displayFor(tenants, tenant),
		Tenants: tenants, Total: len(rev), Page: 1}
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		d.Page = p
	}
	start := (d.Page - 1) * per
	if start > len(rev) {
		start = len(rev)
	}
	end := start + per
	if end > len(rev) {
		end = len(rev)
	}
	d.Runs = rev[start:end]
	if len(d.Runs) > 0 {
		d.FirstRow, d.LastRow = start+1, end
	}
	d.HasPrev, d.PrevPage = d.Page > 1, d.Page-1
	d.HasNext, d.NextPage = end < len(rev), d.Page+1
	s.render(w, "runs.html", d)
}

func (s *Server) render(w http.ResponseWriter, name string, d any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, d); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

// buildLine maps trend points into an SVG polyline within a 900x220 viewport
// (0..100 on the Y axis). Points with no data (-1) are dropped from the line.
func buildLine(trend []store.TrendPoint, get func(store.TrendPoint) float64) lineSeries {
	const w, h, padL, padR, padT, padB = 900.0, 220.0, 40.0, 20.0, 20.0, 30.0
	n := len(trend)
	var ls lineSeries
	pts := ""
	for i, tp := range trend {
		v := get(tp)
		x := padL
		if n > 1 {
			x = padL + (w-padL-padR)*float64(i)/float64(n-1)
		}
		y := padT + (h-padT-padB)*(1-clamp01(v/100))
		dot := chartPoint{X: x, Y: y, Label: tp.Run.CollectedAt.Format("Jan 02"), Val: v, Has: v >= 0}
		ls.Dots = append(ls.Dots, dot)
		if dot.Has {
			if pts != "" {
				pts += " "
			}
			pts += fmt.Sprintf("%.1f,%.1f", x, y)
		}
	}
	ls.Points = pts
	return ls
}

// privilegedDirRolesWeb mirrors the collector's privileged set, for UI flagging.
var privilegedDirRolesWeb = map[string]bool{
	"Global Administrator": true, "Privileged Role Administrator": true,
	"Privileged Authentication Administrator": true, "Security Administrator": true,
	"Conditional Access Administrator": true, "Application Administrator": true,
	"Cloud Application Administrator": true, "User Administrator": true,
	"Authentication Administrator": true, "Exchange Administrator": true,
	"SharePoint Administrator": true, "Hybrid Identity Administrator": true,
	"Intune Administrator": true, "Domain Name Administrator": true,
}

type gridline struct {
	Y, TextY float64
	Label    string
}

// gridlines returns horizontal reference lines at 0/25/50/75/100% matching the
// buildLine viewport math (padT=20, padB=30, h=220).
func gridlines() []gridline {
	const h, padT, padB = 220.0, 20.0, 30.0
	var out []gridline
	for _, v := range []int{100, 75, 50, 25, 0} {
		y := padT + (h-padT-padB)*(1-float64(v)/100)
		out = append(out, gridline{Y: y, TextY: y + 3, Label: fmt.Sprintf("%d", v)})
	}
	return out
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

// Serve starts the HTTP server (blocking).
func Serve(ctx context.Context, addr string, s *Server) error {
	srv := &http.Server{Addr: addr, Handler: s.Routes()}
	return srv.ListenAndServe()
}

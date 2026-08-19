package web

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/auth"
	"github.com/automationpi/govlens/internal/store"
)

func (s *Server) revokeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/requests", s.requestsPage)
	mux.HandleFunc("/revoke/mark", s.revokeMark)
	mux.HandleFunc("/revoke/decide", s.revokeDecide)
	mux.HandleFunc("/revoke/decide-bulk", s.revokeDecideBulk)
}

// revokeMark opens a pending revoke request for one assignment. This only writes
// to GovLens's own queue — it needs no Azure permission and revokes nothing.
func (s *Server) revokeMark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u, ok := requireRole(w, r, "") // any authenticated user may request
	if !ok {
		return
	}
	_ = r.ParseForm()
	n := store.NewRevokeRequest{
		Tenant:        r.FormValue("tenant"),
		Kind:          r.FormValue("kind"),
		TargetIdent:   r.FormValue("ident"),
		Principal:     r.FormValue("principal"),
		PrincipalType: r.FormValue("ptype"),
		Role:          r.FormValue("role"),
		Scope:         r.FormValue("scope"),
		Reason:        r.FormValue("reason"),
		RequestedBy:   u.Email, // real identity, not a form field
		RunID:         parseInt64(r.FormValue("run")),
	}
	if n.Tenant == "" || n.TargetIdent == "" {
		http.Error(w, "missing tenant/ident", http.StatusBadRequest)
		return
	}
	if s.store.IsRoleProtected(r.Context(), n.Role) {
		http.Error(w, "role '"+n.Role+"' is protected (non-revocable) by admin policy", http.StatusForbidden)
		return
	}
	if s.store.TypePolicy(r.Context(), n.PrincipalType) == "blocked" {
		http.Error(w, "revocation of "+n.PrincipalType+"s is disabled by admin policy", http.StatusForbidden)
		return
	}
	if _, err := s.store.CreateRevokeRequest(r.Context(), n); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Background (fetch) request → return the target's open status so the row can
	// update in place, no reload. Plain form posts fall back to a redirect.
	if r.Header.Get("X-Requested-With") == "fetch" {
		open, _ := s.store.OpenRevokeTargets(r.Context(), n.Tenant)
		status := open[n.TargetIdent]
		if status == "" {
			status = "pending"
		}
		writeJSON(w, map[string]string{"status": status})
		return
	}
	anchor := r.FormValue("back")
	if anchor == "" {
		anchor = "rbac"
	}
	http.Redirect(w, r, "/run?run="+r.FormValue("run")+"#"+anchor, http.StatusSeeOther)
}

// revokeDecide records an approve/reject on a pending request (stage 2).
func (s *Server) revokeDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u, ok := requireRole(w, r, "") // authenticated; scope check below
	if !ok {
		return
	}
	_ = r.ParseForm()
	id := parseInt64(r.FormValue("id"))
	approve := r.FormValue("decision") == "approve"
	tenant := r.FormValue("tenant")
	outcome, reason := s.applyRevokeDecision(r.Context(), u, id, approve, r.FormValue("note"))
	dest := "/requests?tenant=" + url.QueryEscape(tenant)
	if outcome == "skipped" {
		dest += "&err=" + url.QueryEscape(reason)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// revokeDecideBulk applies one decision (approve/reject) with a single note to every
// selected revoke request. Revocations are immediate — no expiry. Each is authorized
// against its own scope/type policy; any that can't be applied are skipped and summarized.
func (s *Server) revokeDecideBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u, ok := requireRole(w, r, "")
	if !ok {
		return
	}
	_ = r.ParseForm()
	tenant := r.FormValue("tenant")
	approve := r.FormValue("decision") == "approve"
	note := r.FormValue("note")

	var approved, rejected int
	skips := map[string]int{}
	for _, sid := range r.Form["sel"] {
		id := parseInt64(sid)
		if id == 0 {
			continue
		}
		switch outcome, reason := s.applyRevokeDecision(r.Context(), u, id, approve, note); outcome {
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

// applyRevokeDecision authorizes and applies a single revoke decision. It writes
// nothing to the response — it returns a one-word outcome and, when skipped, a reason.
func (s *Server) applyRevokeDecision(ctx context.Context, u *auth.User, id int64, approve bool, note string) (outcome, reason string) {
	// Scope-aware authorization: global approver/admin, or approver/admin of the
	// request's subscription — unless the principal type requires global approval.
	scope, ptype, err := s.store.RevokeRequestScopeType(ctx, id)
	if err != nil {
		return "skipped", "not found"
	}
	policy := s.store.TypePolicy(ctx, ptype)
	if policy == "blocked" {
		return "skipped", ptype + " revocations disabled"
	}
	if policy == "global" {
		if !u.IsApprover() { // must be a GLOBAL approver/admin
			return "skipped", "needs global approver"
		}
	} else if !u.CanApprove(scope) {
		return "skipped", "not your scope"
	}
	if err := s.store.DecideRevokeRequest(ctx, id, approve, u.Email, note); err != nil {
		return "skipped", err.Error()
	}
	if approve {
		return "approved", ""
	}
	return "rejected", ""
}

// actorRef maps a short handle (the part before @) to a full identity, for the
// legend/appendix under the timeline so the rows can stay compact.
type actorRef struct {
	Handle string
	Email  string
	Name   string
}

const historyPageSize = 20

type requestsData struct {
	Tenant         string
	TenantDisplay  string
	Tenants        []store.TenantInfo
	PendingGrants  []store.RevokeRequest
	PendingRevokes []store.RevokeRequest
	PendingDrift   []store.RevokeRequest // out-of-band changes awaiting review
	History        []store.RevokeRequest // combined grant+revoke, paginated + visibility-filtered
	GrantLive      bool
	Actors         []actorRef // legend for the handles shown in timelines
	User           *auth.User
	Notice         string

	// History search + pager.
	Search   string
	Page     int
	PageSize int
	Total    int
	FirstRow int
	LastRow  int
	HasPrev  bool
	HasNext  bool
	PrevPage int
	NextPage int
}

// canSeeRequest is the visibility matrix: a user sees their own requests, a global
// approver/admin sees everything, and a subscription admin/approver sees requests
// scoped to their subscription(s).
func canSeeRequest(u *auth.User, r store.RevokeRequest) bool {
	if u == nil {
		return false
	}
	if strings.EqualFold(r.RequestedBy, u.Email) {
		return true
	}
	if u.IsApprover() { // global approver (includes global admin)
		return true
	}
	return u.CanApprove(r.Scope) || u.IsAdminOf(r.Scope)
}

// scopedSubsOf lists the subscription ids where the user is a scoped admin/approver.
func scopedSubsOf(u *auth.User) []string {
	var out []string
	for scope, roles := range u.Grants {
		if scope == "*" {
			continue
		}
		for _, role := range roles {
			if role == "admin" || role == "approver" {
				out = append(out, scope)
				break
			}
		}
	}
	return out
}

func (s *Server) requestsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tenant := s.resolveTenant(r, tenants)
	u := userOf(r)
	d := requestsData{Tenant: tenant, TenantDisplay: displayFor(tenants, tenant), Tenants: tenants,
		User: u, Notice: r.URL.Query().Get("err"), PageSize: historyPageSize,
		Search: strings.TrimSpace(r.URL.Query().Get("q"))}
	d.GrantLive = s.store.GrantReadinessAt(ctx, tenant, time.Now()).Live

	// Pending queues (grant + revoke), filtered to what this viewer may see.
	if pg, _ := s.store.GrantRequests(ctx, tenant, "pending"); pg != nil {
		for _, g := range pg {
			if canSeeRequest(u, g) {
				d.PendingGrants = append(d.PendingGrants, g)
			}
		}
	}
	if pr, _ := s.store.RevokeRequests(ctx, tenant, "pending"); pr != nil {
		for _, rq := range pr {
			if canSeeRequest(u, rq) {
				d.PendingRevokes = append(d.PendingRevokes, rq)
			}
		}
	}
	if pd, _ := s.store.DriftRequests(ctx, tenant, "pending"); pd != nil {
		for _, dr := range pd {
			if canSeeRequest(u, dr) {
				d.PendingDrift = append(d.PendingDrift, dr)
			}
		}
	}

	// History: visibility-filtered, searchable, paginated (in SQL).
	d.Page = 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		d.Page = p
	}
	hq := store.HistoryQuery{ViewerEmail: u.Email, SeeAll: u.IsApprover(),
		ScopedSubs: scopedSubsOf(u), Search: d.Search,
		Limit: historyPageSize, Offset: (d.Page - 1) * historyPageSize}
	hist, total, err := s.store.AccessHistory(ctx, tenant, hq)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	d.History, d.Total = hist, total
	if total > 0 {
		d.FirstRow = (d.Page-1)*historyPageSize + 1
		d.LastRow = d.FirstRow + len(hist) - 1
	}
	d.HasPrev, d.PrevPage = d.Page > 1, d.Page-1
	d.HasNext, d.NextPage = d.Page*historyPageSize < total, d.Page+1

	// Actor legend from the rows actually shown.
	names := map[string]string{}
	if users, err := s.store.ListUsers(ctx); err == nil {
		for _, usr := range users {
			names[strings.ToLower(usr.Email)] = usr.Name
		}
	}
	seen := map[string]bool{}
	addActor := func(email string) {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" || email == "unknown" || seen[email] {
			return
		}
		seen[email] = true
		h := handleOf(email)
		name := strings.TrimSpace(names[email])
		if len([]rune(name)) < 2 || strings.EqualFold(name, h) {
			name = ""
		}
		d.Actors = append(d.Actors, actorRef{Handle: h, Email: email, Name: name})
	}
	for _, r := range d.PendingGrants {
		addActor(r.RequestedBy)
	}
	for _, r := range d.PendingRevokes {
		addActor(r.RequestedBy)
	}
	for _, r := range d.PendingDrift {
		addActor(r.RequestedBy)
	}
	for _, r := range d.History {
		addActor(r.RequestedBy)
		addActor(r.DecidedBy)
	}
	sort.Slice(d.Actors, func(i, j int) bool { return d.Actors[i].Handle < d.Actors[j].Handle })
	s.render(w, "requests.html", d)
}

// handleOf returns the local part of an email (before @); non-emails pass through.
func handleOf(who string) string {
	if i := strings.IndexByte(who, '@'); i > 0 {
		return who[:i]
	}
	return who
}

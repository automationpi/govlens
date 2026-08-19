package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/automationpi/govlens/internal/auth"
)

func (s *Server) driftRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/drift/decide", s.driftDecide)
	mux.HandleFunc("/drift/decide-bulk", s.driftDecideBulk)
}

// driftDecide resolves one out-of-band (drift) request. Approve blesses the access
// (optionally with an expiry, which makes it a governed, auto-expiring grant);
// reject queues the assignment for removal by the remediator.
func (s *Server) driftDecide(w http.ResponseWriter, r *http.Request) {
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

	outcome, reason := s.applyDriftDecision(ctx, u, id, approve, note, days, permanent)
	dest := "/requests?tenant=" + url.QueryEscape(tenant)
	if outcome == "skipped" {
		dest += "&err=" + url.QueryEscape(reason)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// driftDecideBulk applies one decision with a shared note (and, for approvals, a
// shared expiry) to every selected drift request.
func (s *Server) driftDecideBulk(w http.ResponseWriter, r *http.Request) {
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
		switch outcome, reason := s.applyDriftDecision(ctx, u, id, approve, note, days, permanent); outcome {
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

// applyDriftDecision authorizes and applies one drift decision. It writes nothing to
// the response; it returns a one-word outcome and, when skipped, a reason. Approve
// with a positive day count blesses-with-expiry; permanent or no days blesses as-is;
// reject enqueues removal.
func (s *Server) applyDriftDecision(ctx context.Context, u *auth.User, id int64, approve bool, note string, days int, permanent bool) (outcome, reason string) {
	req, err := s.store.GetAccessRequest(ctx, id)
	if err != nil || req.Action != "drift" || req.Status != "pending" {
		return "skipped", "not found or already decided"
	}
	if !u.IsApprover() && !u.CanApprove(req.Scope) {
		return "skipped", "not your scope"
	}
	if !approve {
		if err := s.store.DecideDrift(ctx, id, false, u.Email, note, nil); err != nil {
			return "skipped", err.Error()
		}
		return "rejected", ""
	}
	var expiresAt *time.Time
	if !permanent && days > 0 {
		t := time.Now().Add(time.Duration(days) * 24 * time.Hour)
		expiresAt = &t
	}
	if err := s.store.DecideDrift(ctx, id, true, u.Email, note, expiresAt); err != nil {
		return "skipped", err.Error()
	}
	return "approved", ""
}

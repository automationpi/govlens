package web

import (
	"encoding/json"
	"net/http"
)

// The JSON API exposes the same store queries the dashboard renders, so any
// client (a SPA, a script, or the MCP server) reads identical governance data.
// All endpoints take an optional ?tenant= (defaults to the server's tenant).

func (s *Server) apiRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/tenants", s.apiTenants)
	mux.HandleFunc("/api/runs", s.apiRuns)
	mux.HandleFunc("/api/trend", s.apiTrend)
	mux.HandleFunc("/api/drift", s.apiDrift)
	mux.HandleFunc("/api/findings", s.apiFindings)
}

func (s *Server) tenantOf(r *http.Request) string {
	if t := r.URL.Query().Get("tenant"); t != "" {
		return t
	}
	return s.tenant
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) apiTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.Tenants(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"tenants": ts})
}

func (s *Server) apiRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.Runs(r.Context(), s.tenantOf(r))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"tenant": s.tenantOf(r), "runs": runs})
}

func (s *Server) apiTrend(w http.ResponseWriter, r *http.Request) {
	tp, err := s.store.Trend(r.Context(), s.tenantOf(r))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"tenant": s.tenantOf(r), "trend": tp})
}

func (s *Server) apiDrift(w http.ResponseWriter, r *http.Request) {
	newer, older, rows, suppressed, err := s.store.Drift(r.Context(), s.tenantOf(r))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"tenant": s.tenantOf(r), "newer": newer, "older": older,
		"drift": rows, "suppressed": suppressed,
	})
}

// apiFindings returns non-passing controls for the latest run (or ?run=<id>).
func (s *Server) apiFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := s.tenantOf(r)
	runs, err := s.store.Runs(ctx, tenant)
	if err != nil {
		fail(w, err)
		return
	}
	if len(runs) == 0 {
		writeJSON(w, map[string]any{"tenant": tenant, "findings": []any{}})
		return
	}
	runID := runs[len(runs)-1].ID
	if q := r.URL.Query().Get("run"); q != "" && q != "latest" {
		if id := parseInt64(q); id > 0 {
			runID = id
		}
	}
	limit := 100
	if l := parseInt64(r.URL.Query().Get("limit")); l > 0 {
		limit = int(l)
	}
	fs, err := s.store.FailingFindings(ctx, runID, r.URL.Query().Get("sub"), limit)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"tenant": tenant, "run": runID, "findings": fs})
}

func parseInt64(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

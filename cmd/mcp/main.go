// Command mcp exposes govlens governance data to AI clients over MCP
// (stdio). It reuses the same store queries as the dashboard and JSON API, so
// Claude reads exactly the data the FE renders.
//
//	DATABASE_URL=postgres://... govlens-mcp
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/automationpi/govlens/internal/store"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	s := server.NewMCPServer("govlens", "0.1.0",
		server.WithToolCapabilities(true))
	h := &handlers{st: st}

	s.AddTool(mcp.NewTool("list_tenants",
		mcp.WithDescription("List the Azure tenants that have ingested governance runs.")),
		h.listTenants)

	s.AddTool(mcp.NewTool("compliance_trend",
		mcp.WithDescription("Compliance and security posture over time for a tenant: Azure Policy compliance %, Maester pass rate %, RBAC count, and Conditional Access counts per run."),
		mcp.WithString("tenant", mcp.Description("Tenant name; defaults to the most recently active tenant."))),
		h.trend)

	s.AddTool(mcp.NewTool("drift",
		mcp.WithDescription("RBAC and Conditional Access changes between a tenant's two most recent runs (added/removed/changed). Notes any 'suppressed' kinds whose collector did not run, so a missing source is never a false mass-removal."),
		mcp.WithString("tenant", mcp.Description("Tenant name; defaults to the most recently active tenant."))),
		h.drift)

	s.AddTool(mcp.NewTool("findings",
		mcp.WithDescription("Non-passing controls (failed Maester tests + non-compliant Azure Policy assignments) for a tenant's latest run, most severe first."),
		mcp.WithString("tenant", mcp.Description("Tenant name; defaults to the most recently active tenant.")),
		mcp.WithString("limit", mcp.Description("Max findings to return (default 100)."))),
		h.findings)

	s.AddTool(mcp.NewTool("run_summary",
		mcp.WithDescription("Headline governance numbers for a tenant's latest run: compliance %, Maester pass %, CA enabled/total, RBAC count, failing controls, and which collectors contributed."),
		mcp.WithString("tenant", mcp.Description("Tenant name; defaults to the most recently active tenant."))),
		h.runSummary)

	if err := server.ServeStdio(s); err != nil {
		log.Fatal(err)
	}
}

type handlers struct{ st *store.Store }

// tenant resolves the requested tenant, or the most recently active one.
func (h *handlers) tenant(ctx context.Context, req mcp.CallToolRequest) (string, error) {
	if t := req.GetString("tenant", ""); t != "" {
		return t, nil
	}
	ts, err := h.st.Tenants(ctx)
	if err != nil {
		return "", err
	}
	if len(ts) == 0 {
		return "", fmt.Errorf("no tenants ingested yet")
	}
	return ts[0].ID, nil
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func (h *handlers) listTenants(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ts, err := h.st.Tenants(ctx)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return jsonResult(map[string]any{"tenants": ts})
}

func (h *handlers) trend(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tenant, err := h.tenant(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tp, err := h.st.Trend(ctx, tenant)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	type point struct {
		Date         string  `json:"date"`
		PolicyPct    float64 `json:"policy_compliance_pct"`
		MaesterPct   float64 `json:"maester_pass_pct"`
		RBAC         int     `json:"rbac_assignments"`
		CAEnabled    int     `json:"ca_enabled"`
		CATotal      int     `json:"ca_total"`
		FailingCtrls int     `json:"failing_controls"`
	}
	out := make([]point, 0, len(tp))
	for _, p := range tp {
		out = append(out, point{
			Date: p.Run.CollectedAt.Format("2006-01-02"), PolicyPct: round1(p.PolicyPct),
			MaesterPct: round1(p.MaesterPct), RBAC: p.RBACCount, CAEnabled: p.CAEnabled,
			CATotal: p.CATotal, FailingCtrls: p.FailedControl,
		})
	}
	return jsonResult(map[string]any{"tenant": tenant, "trend": out, "note": "-1 means that source was not collected in that run"})
}

func (h *handlers) drift(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tenant, err := h.tenant(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	newer, older, rows, suppressed, err := h.st.Drift(ctx, tenant)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if newer == nil {
		return jsonResult(map[string]any{"tenant": tenant, "note": "need at least two runs to compute drift"})
	}
	return jsonResult(map[string]any{
		"tenant": tenant,
		"from":   older.CollectedAt.Format("2006-01-02"), "to": newer.CollectedAt.Format("2006-01-02"),
		"changes": rows, "suppressed": suppressed,
	})
}

func (h *handlers) findings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tenant, err := h.tenant(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	runs, err := h.st.Runs(ctx, tenant)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if len(runs) == 0 {
		return jsonResult(map[string]any{"tenant": tenant, "findings": []any{}})
	}
	limit := req.GetInt("limit", 100)
	fs, err := h.st.FailingFindings(ctx, runs[len(runs)-1].ID, "", limit)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return jsonResult(map[string]any{"tenant": tenant, "run_date": runs[len(runs)-1].CollectedAt.Format("2006-01-02"), "findings": fs})
}

func (h *handlers) runSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tenant, err := h.tenant(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tp, err := h.st.Trend(ctx, tenant)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if len(tp) == 0 {
		return jsonResult(map[string]any{"tenant": tenant, "note": "no runs ingested"})
	}
	latest := tp[len(tp)-1]
	return jsonResult(map[string]any{
		"tenant":                tenant,
		"run_date":              latest.Run.CollectedAt.Format("2006-01-02"),
		"collected_sources":     latest.Run.Sources,
		"policy_compliance_pct": round1(latest.PolicyPct),
		"maester_pass_pct":      round1(latest.MaesterPct),
		"ca_enabled":            latest.CAEnabled,
		"ca_total":              latest.CATotal,
		"rbac_assignments":      latest.RBACCount,
		"directory_roles":       latest.DirRoles,
		"privileged_roles":      latest.Privileged,
		"global_admins":         latest.GlobalAdmins,
		"failing_controls":      latest.FailedControl,
	})
}

func round1(f float64) float64 {
	if f < 0 {
		return f // -1 sentinel = not collected
	}
	return float64(int(f*10+0.5)) / 10
}

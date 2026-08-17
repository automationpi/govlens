package ingest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/store"
)

// --- Maester (Invoke-Maester -OutputJson) ---
// Field names verified against a real Maester results file. Note: there is no
// per-test "Severity" field in current Maester output — severity is inferred
// from the Tag list (e.g. "L1"/"L2", "High"). Top-level counts are authoritative.
type maesterResult struct {
	Result      string  `json:"Result"`
	TotalCount  float64 `json:"TotalCount"`
	PassedCount float64 `json:"PassedCount"`
	FailedCount float64 `json:"FailedCount"`
	SkippedCount float64 `json:"SkippedCount"`
	ExecutedAt  string          `json:"ExecutedAt"`
	TenantID    string          `json:"TenantId"`
	TenantName  string          `json:"TenantName"`
	// Real Maester serializes CurrentVersion as a System.Version object
	// ({"Major":2,"Minor":2,...}), while our fixtures use a plain string — accept both.
	Version json.RawMessage `json:"CurrentVersion"`
	Tests       []struct {
		ID       string          `json:"Id"`
		Title    string          `json:"Title"`
		Name     string          `json:"Name"`
		Result   string          `json:"Result"` // Passed | Failed | NotRun | Skipped
		Block    string          `json:"Block"`
		HelpURL  string          `json:"HelpUrl"`
		Severity string          `json:"Severity"` // usually empty; kept for future versions
		Tag      json.RawMessage `json:"Tag"`
	} `json:"Tests"`
}

// runMeta carries run identity a collector embeds in its output, so the adapter
// can stamp collected_at/tenant without a manifest when one isn't provided.
type runMeta struct {
	CollectedAt time.Time
	Tenant      string
	ToolVersion string
}

func parseMaester(path string) ([]store.Metric, []store.Finding, runMeta, error) {
	var meta runMeta
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, meta, err
	}
	var mr maesterResult
	if err := json.Unmarshal(b, &mr); err != nil {
		return nil, nil, meta, err
	}

	var findings []store.Finding
	var passed, failed, notrun float64
	for _, t := range mr.Tests {
		status := strings.ToLower(t.Result)
		switch status {
		case "passed":
			passed++
		case "failed":
			failed++
		default:
			notrun++
			status = "notrun"
		}
		id := firstNonEmpty(t.ID, t.Name)
		title := firstNonEmpty(t.Title, t.Name, id)
		findings = append(findings, store.Finding{
			Domain:    "entra",
			Source:    "maester",
			ControlID: id,
			Title:     title,
			Severity:  severityFromMaester(t.Severity, t.Tag),
			Status:    status,
			Category:  t.Block,
			HelpURL:   t.HelpURL,
		})
	}

	// Prefer Maester's own top-level counts (they include tests we don't emit as
	// individual failures); fall back to what we counted.
	if mr.TotalCount > 0 {
		passed, failed = mr.PassedCount, mr.FailedCount
		notrun = mr.TotalCount - mr.PassedCount - mr.FailedCount
	}
	metrics := []store.Metric{
		{Domain: "entra", Category: "maester", Key: "passed", Value: passed},
		{Domain: "entra", Category: "maester", Key: "failed", Value: failed},
		{Domain: "entra", Category: "maester", Key: "notrun", Value: notrun},
	}

	if t, err := time.Parse(time.RFC3339, mr.ExecutedAt); err == nil {
		meta.CollectedAt = t
	}
	meta.Tenant = firstNonEmpty(mr.TenantName, mr.TenantID)
	meta.ToolVersion = maesterVersion(mr.Version)
	return metrics, findings, meta, nil
}

// maesterVersion renders CurrentVersion whether it's a JSON string ("2.2.0") or
// a System.Version object ({"Major":2,"Minor":2,"Build":0}).
func maesterVersion(raw json.RawMessage) string {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return ""
	}
	if strings.HasPrefix(t, "\"") {
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	}
	var v struct{ Major, Minor, Build int }
	if err := json.Unmarshal(raw, &v); err == nil {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
	}
	return ""
}

// severityFromMaester maps an explicit Severity if present, else infers from the
// CIS-style Tag list, else Info.
func severityFromMaester(explicit string, rawTag json.RawMessage) string {
	if s := normSeverity(explicit); s != "Info" {
		return s
	}
	var tags []string
	_ = json.Unmarshal(rawTag, &tags)
	for _, t := range tags {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "high", "critical", "l1", "cis e3 level 1":
			return "High"
		case "medium", "l2", "cis e3 level 2":
			return "Medium"
		case "low":
			return "Low"
		}
	}
	return "Info"
}

func normSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "critical":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}

// --- EntraExporter Conditional Access policies ---
// EntraExporter writes one JSON file per policy under
// Identity/Conditional/AccessPolicies/<id>.json. We also accept a single bare
// array or a Graph {"value":[...]} envelope (fixtures / other exporters).
type caPolicy struct {
	ID            string `json:"id"`
	DisplayName   string `json:"displayName"`
	State         string `json:"state"` // enabled | disabled | enabledForReportingButNotEnforced
	GrantControls struct {
		BuiltInControls []string `json:"builtInControls"`
	} `json:"grantControls"`
}

// parseCA loads Conditional Access policies from either a single file (array or
// envelope) or a directory of per-object JSON files.
func parseCA(path string) ([]store.Metric, []store.Assignment, error) {
	policies, err := loadCAPolicies(path)
	if err != nil {
		return nil, nil, err
	}
	var assigns []store.Assignment
	var enabled, reportOnly, disabled float64
	for _, p := range policies {
		switch p.State {
		case "enabled":
			enabled++
		case "enabledForReportingButNotEnforced":
			reportOnly++
		default:
			disabled++
		}
		assigns = append(assigns, store.Assignment{
			Domain:  "entra",
			Kind:    "ca_policy",
			Ident:   p.ID,
			Role:    p.State, // "role" column doubles as CA state so drift catches flips
			Display: p.DisplayName,
			Scope:   strings.Join(p.GrantControls.BuiltInControls, "+"),
		})
	}
	metrics := []store.Metric{
		{Domain: "entra", Category: "ca_policy", Key: "total", Value: float64(len(policies))},
		{Domain: "entra", Category: "ca_policy", Key: "enabled", Value: enabled},
		{Domain: "entra", Category: "ca_policy", Key: "report_only", Value: reportOnly},
		{Domain: "entra", Category: "ca_policy", Key: "disabled", Value: disabled},
	}
	return metrics, assigns, nil
}

func loadCAPolicies(path string) ([]caPolicy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		// EntraExporter nests each object in its own subfolder
		// (AccessPolicies/<id>/<id>.json), so recurse for every *.json.
		var files []string
		_ = filepath.WalkDir(path, func(p string, e fs.DirEntry, err error) error {
			if err == nil && !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		var out []caPolicy
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			ps, err := decodeCA(b) // a per-object file may still be one object
			if err != nil {
				return nil, err
			}
			out = append(out, ps...)
		}
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeCA(b)
}

// decodeCA accepts a single object, a bare array, or a {"value":[...]} envelope.
func decodeCA(b []byte) ([]caPolicy, error) {
	trimmed := strings.TrimLeft(string(b), " \t\r\n")
	switch {
	case strings.HasPrefix(trimmed, "["):
		var arr []caPolicy
		return arr, json.Unmarshal(b, &arr)
	case strings.Contains(trimmed, `"value"`):
		var env struct {
			Value []caPolicy `json:"value"`
		}
		if err := json.Unmarshal(b, &env); err == nil && env.Value != nil {
			return env.Value, nil
		}
		fallthrough
	default:
		var one caPolicy
		if err := json.Unmarshal(b, &one); err != nil {
			return nil, err
		}
		if one.ID == "" {
			return nil, nil
		}
		return []caPolicy{one}, nil
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

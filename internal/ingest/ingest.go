// Package ingest reads a single collection run's artifacts (produced in the
// customer tenant by AzGovViz / Maester / EntraExporter) and normalizes them
// into the store. The collectors never run here; we only consume their files.
//
// Expected layout of a run directory:
//
//	<run>/manifest.json                              (tenant + collected_at)
//	<run>/azgovviz/policy_compliance.csv             (Azure Policy compliance)
//	<run>/azgovviz/rbac.csv                          (role assignments)
//	<run>/maester/test-results.json                  (Entra/M365 security tests)
//	<run>/entraexporter/ConditionalAccessPolicies.json
//
// Any missing file is simply skipped, so partial runs still ingest.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/automationpi/govlens/internal/store"
)

type manifest struct {
	Tenant      string    `json:"tenant"`
	CollectedAt time.Time `json:"collected_at"`
}

// Run ingests one run directory that already follows the normalized contract
// (as produced by collect.ps1 or the fixtures). For raw collector output, use
// RunNative in adapter.go.
func Run(ctx context.Context, s *store.Store, dir string) (int64, error) {
	mf, err := readManifest(dir)
	if err != nil {
		return 0, err
	}
	rd := store.RunData{Tenant: mf.Tenant, CollectedAt: mf.CollectedAt, Label: filepath.Base(dir)}

	if p := filepath.Join(dir, "azgovviz", "policy_compliance.csv"); exists(p) {
		m, f, err := parsePolicyCompliance(p)
		if err != nil {
			return 0, fmt.Errorf("policy_compliance: %w", err)
		}
		rd.Metrics = append(rd.Metrics, m...)
		rd.Findings = append(rd.Findings, f...)
		rd.Sources = append(rd.Sources, store.SrcPolicy)
	}
	if p := filepath.Join(dir, "azgovviz", "rbac.csv"); exists(p) {
		m, a, err := parseRBAC(p)
		if err != nil {
			return 0, fmt.Errorf("rbac: %w", err)
		}
		rd.Metrics = append(rd.Metrics, m...)
		rd.Assignments = append(rd.Assignments, a...)
		rd.Sources = append(rd.Sources, store.SrcRBAC)
	}
	if p := filepath.Join(dir, "maester", "test-results.json"); exists(p) {
		m, f, _, err := parseMaester(p)
		if err != nil {
			return 0, fmt.Errorf("maester: %w", err)
		}
		rd.Metrics = append(rd.Metrics, m...)
		rd.Findings = append(rd.Findings, f...)
		rd.Sources = append(rd.Sources, store.SrcMaester)
	}
	// Accept either the normalized single file or a per-object directory.
	for _, p := range []string{
		filepath.Join(dir, "entraexporter", "ConditionalAccessPolicies.json"),
		filepath.Join(dir, "entraexporter", "ConditionalAccessPolicies"),
	} {
		if exists(p) {
			m, a, err := parseCA(p)
			if err != nil {
				return 0, fmt.Errorf("conditional_access: %w", err)
			}
			rd.Metrics = append(rd.Metrics, m...)
			rd.Assignments = append(rd.Assignments, a...)
			rd.Sources = append(rd.Sources, store.SrcCA)
			break
		}
	}

	return s.ReplaceRun(ctx, rd)
}

func readManifest(dir string) (manifest, error) {
	var mf manifest
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return mf, fmt.Errorf("read manifest: %w", err)
	}
	if err := json.Unmarshal(b, &mf); err != nil {
		return mf, fmt.Errorf("parse manifest: %w", err)
	}
	if mf.Tenant == "" {
		mf.Tenant = "default"
	}
	if mf.CollectedAt.IsZero() {
		return mf, fmt.Errorf("manifest missing collected_at")
	}
	return mf, nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

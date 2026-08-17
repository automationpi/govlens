package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/store"
)

// Spec drives native discovery. Entries are lower-cased substrings matched
// against file/dir base names, so they survive the MG-id / product prefixes the
// real collectors add (e.g. "AzGovViz_<mgid>_RoleAssignments.csv"). Override any
// field via a JSON spec file when a real run uses different naming.
type Spec struct {
	RBAC          []string `json:"rbac"`            // AzGovViz role-assignment CSV
	Policy        []string `json:"policy"`          // AzGovViz policy-compliance CSV
	Maester       []string `json:"maester"`         // Maester results JSON
	CADir         []string `json:"ca_dir"`          // EntraExporter per-object CA folder
	CAFile        []string `json:"ca_file"`         // single-file CA export
	PolicyColumns []string `json:"policy_columns"`  // header that proves a CSV is compliance data
}

// DefaultSpec encodes what the real tools emit (verified against their source).
func DefaultSpec() Spec {
	return Spec{
		RBAC:    []string{"roleassignments"},
		Policy:  []string{"policycompliancestates", "policy_compliance"},
		Maester: []string{"test-results", "testresults"},
		CADir:   []string{"accesspolicies", "conditionalaccesspolicies"},
		CAFile:  []string{"conditionalaccesspolicies.json"},
		// A candidate policy CSV is only used if its header has one of these,
		// so AzGovViz's *PolicyAssignments*.csv (no compliance counts) is skipped.
		PolicyColumns: []string{"CompliantResources", "NonCompliantResources", "ComplianceState", "CompliantResourceCount"},
	}
}

// LoadSpec merges a JSON override file onto DefaultSpec (empty fields keep defaults).
func LoadSpec(path string) (Spec, error) {
	s := DefaultSpec()
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	var ov Spec
	if err := json.Unmarshal(b, &ov); err != nil {
		return s, err
	}
	if len(ov.RBAC) > 0 {
		s.RBAC = ov.RBAC
	}
	if len(ov.Policy) > 0 {
		s.Policy = ov.Policy
	}
	if len(ov.Maester) > 0 {
		s.Maester = ov.Maester
	}
	if len(ov.CADir) > 0 {
		s.CADir = ov.CADir
	}
	if len(ov.CAFile) > 0 {
		s.CAFile = ov.CAFile
	}
	if len(ov.PolicyColumns) > 0 {
		s.PolicyColumns = ov.PolicyColumns
	}
	return s, nil
}

type discovered struct {
	rbac, policy, maester, caFile, caDir string
}

// RunNative discovers raw collector artifacts under rawDir and loads them as one
// run. tenant/collectedAt override the derived values when non-zero.
func RunNative(ctx context.Context, s *store.Store, rawDir string, spec Spec, tenant string, collectedAt time.Time) (int64, error) {
	d, err := discover(rawDir, spec)
	if err != nil {
		return 0, err
	}

	rd := store.RunData{Label: filepath.Base(rawDir)}
	var meta runMeta

	if d.policy != "" {
		m, f, err := parsePolicyCompliance(d.policy)
		if err != nil {
			return 0, fmt.Errorf("policy %s: %w", d.policy, err)
		}
		rd.Metrics, rd.Findings = append(rd.Metrics, m...), append(rd.Findings, f...)
		rd.Sources = append(rd.Sources, store.SrcPolicy)
	}
	if d.rbac != "" {
		m, a, err := parseRBAC(d.rbac)
		if err != nil {
			return 0, fmt.Errorf("rbac %s: %w", d.rbac, err)
		}
		rd.Metrics, rd.Assignments = append(rd.Metrics, m...), append(rd.Assignments, a...)
		rd.Sources = append(rd.Sources, store.SrcRBAC)
	}
	if d.maester != "" {
		m, f, mt, err := parseMaester(d.maester)
		if err != nil {
			return 0, fmt.Errorf("maester %s: %w", d.maester, err)
		}
		rd.Metrics, rd.Findings, meta = append(rd.Metrics, m...), append(rd.Findings, f...), mt
		rd.Sources = append(rd.Sources, store.SrcMaester)
	}
	caPath := d.caDir
	if caPath == "" {
		caPath = d.caFile
	}
	if caPath != "" {
		m, a, err := parseCA(caPath)
		if err != nil {
			return 0, fmt.Errorf("ca %s: %w", caPath, err)
		}
		rd.Metrics, rd.Assignments = append(rd.Metrics, m...), append(rd.Assignments, a...)
		rd.Sources = append(rd.Sources, store.SrcCA)
	}

	// Resolve run identity: explicit flags > manifest.json > Maester ExecutedAt.
	rd.Tenant, rd.CollectedAt = tenant, collectedAt
	if mf, err := readManifest(rawDir); err == nil {
		if rd.Tenant == "" {
			rd.Tenant = mf.Tenant
		}
		if rd.CollectedAt.IsZero() {
			rd.CollectedAt = mf.CollectedAt
		}
	}
	if rd.Tenant == "" {
		rd.Tenant = firstNonEmpty(meta.Tenant, "default")
	}
	if rd.CollectedAt.IsZero() {
		rd.CollectedAt = meta.CollectedAt
	}
	if rd.CollectedAt.IsZero() {
		return 0, fmt.Errorf("could not determine collected_at: pass -collected-at, add a manifest.json, or include Maester output (has ExecutedAt)")
	}
	if meta.ToolVersion != "" {
		rd.Label = fmt.Sprintf("%s (maester %s)", rd.Label, meta.ToolVersion)
	}

	return s.ReplaceRun(ctx, rd)
}

// discover walks rawDir once and classifies files/dirs by the spec substrings.
// First match of each kind wins; the CA folder is preferred over a CA file.
func discover(rawDir string, spec Spec) (discovered, error) {
	var d discovered
	err := filepath.WalkDir(rawDir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := strings.ToLower(e.Name())
		if e.IsDir() {
			if d.caDir == "" && containsAny(base, spec.CADir) {
				d.caDir = p
			}
			return nil
		}
		switch {
		case d.rbac == "" && containsAny(base, spec.RBAC):
			d.rbac = p
		case d.maester == "" && containsAny(base, spec.Maester):
			d.maester = p
		case d.caFile == "" && containsAny(base, spec.CAFile):
			d.caFile = p
		case d.policy == "" && containsAny(base, spec.Policy) && headerHasAny(p, spec.PolicyColumns):
			// Guard: only accept a CSV that actually carries compliance columns,
			// so *PolicyAssignments*.csv is not mistaken for compliance data.
			d.policy = p
		}
		return nil
	})
	return d, err
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// headerHasAny reports whether the CSV's header row contains any of the columns.
func headerHasAny(path string, cols []string) bool {
	if len(cols) == 0 {
		return true
	}
	idx, _, err := readCSV(path)
	if err != nil {
		return false
	}
	for _, c := range cols {
		if _, ok := idx[c]; ok {
			return true
		}
	}
	return false
}

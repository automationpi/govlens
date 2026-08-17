package ingest

import (
	"encoding/csv"
	"os"
	"strconv"
	"strings"

	"github.com/automationpi/govlens/internal/store"
)

// readCSV returns a header->index map and the remaining rows. It is tolerant of
// column order and extra columns, which matters because AzGovViz CSV layouts
// shift between versions.
func readCSV(path string) (map[string]int, [][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // ragged rows tolerated
	recs, err := r.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(recs) == 0 {
		return map[string]int{}, nil, nil
	}
	idx := map[string]int{}
	for i, h := range recs[0] {
		idx[strings.TrimSpace(h)] = i
	}
	return idx, recs[1:], nil
}

func cell(idx map[string]int, row []string, name string) string {
	if i, ok := idx[name]; ok && i < len(row) {
		return strings.TrimSpace(row[i])
	}
	return ""
}

// cellAny returns the first present, non-empty column among candidate names.
// This absorbs column-name differences across AzGovViz versions and our fixtures.
func cellAny(idx map[string]int, row []string, names ...string) string {
	for _, n := range names {
		if v := cell(idx, row, n); v != "" {
			return v
		}
	}
	return ""
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

// parsePolicyCompliance turns AzGovViz's per-assignment compliance CSV into one
// finding per assignment plus aggregate resource/assignment metrics.
func parsePolicyCompliance(path string) ([]store.Metric, []store.Finding, error) {
	idx, rows, err := readCSV(path)
	if err != nil {
		return nil, nil, err
	}
	var findings []store.Finding
	var compRes, nonCompRes, nonCompAssign, totalAssign float64
	for _, row := range rows {
		name := cellAny(idx, row, "PolicyAssignmentName", "Policy Assignment Name")
		if name == "" {
			continue
		}
		state := cellAny(idx, row, "ComplianceState", "State")
		compliant := atoi(cellAny(idx, row, "CompliantResources", "CompliantResourceCount", "Compliant"))
		nonCompliant := atoi(cellAny(idx, row, "NonCompliantResources", "NonCompliantResourceCount", "NonCompliant"))
		compRes += float64(compliant)
		nonCompRes += float64(nonCompliant)
		totalAssign++

		status := "compliant"
		if !strings.EqualFold(state, "Compliant") || nonCompliant > 0 {
			status = "non_compliant"
			nonCompAssign++
		}
		findings = append(findings, store.Finding{
			Domain:    "azure",
			Source:    "azgovviz-policy",
			ControlID: cellAny(idx, row, "PolicyDefinitionName", "Policy"),
			Title:     name,
			Severity:  severityForPolicy(nonCompliant),
			Status:    status,
			Category:  cellAny(idx, row, "Category", "Policy Category"),
			Scope:     cellAny(idx, row, "Scope", "MgOrSub"),
		})
	}
	metrics := []store.Metric{
		{Domain: "azure", Category: "policy_compliance", Key: "compliant_resources", Value: compRes},
		{Domain: "azure", Category: "policy_compliance", Key: "noncompliant_resources", Value: nonCompRes},
		{Domain: "azure", Category: "policy_compliance", Key: "noncompliant_assignments", Value: nonCompAssign},
		{Domain: "azure", Category: "policy_compliance", Key: "total_assignments", Value: totalAssign},
	}
	return metrics, findings, nil
}

func severityForPolicy(nonCompliant int) string {
	switch {
	case nonCompliant == 0:
		return "Info"
	case nonCompliant >= 10:
		return "High"
	case nonCompliant >= 3:
		return "Medium"
	default:
		return "Low"
	}
}

// parseRBAC turns AzGovViz's role-assignment CSV into assignment rows for drift
// tracking plus a total count metric.
func parseRBAC(path string) ([]store.Metric, []store.Assignment, error) {
	idx, rows, err := readCSV(path)
	if err != nil {
		return nil, nil, err
	}
	var assigns []store.Assignment
	for _, row := range rows {
		// Real AzGovViz uses RoleAssignment* column names; fixtures use the short
		// forms. cellAny accepts either.
		id := cellAny(idx, row, "RoleAssignmentId")
		if id == "" {
			continue
		}
		role := cellAny(idx, row, "RoleDefinitionName")
		scope := cellAny(idx, row, "RoleAssignmentScope", "Scope")
		principal := cellAny(idx, row, "RoleAssignmentIdentityDisplayname", "PrincipalDisplayName")
		ptype := cellAny(idx, row, "RoleAssignmentIdentityObjectType", "PrincipalType")
		assigns = append(assigns, store.Assignment{
			Domain:        "azure",
			Kind:          "rbac",
			Ident:         id,
			Principal:     principal,
			PrincipalType: ptype,
			Role:          role,
			Scope:         scope,
			Display:       principal + " — " + role,
		})
	}
	metrics := []store.Metric{
		{Domain: "azure", Category: "rbac", Key: "count", Value: float64(len(assigns))},
	}
	return metrics, assigns, nil
}

package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile is a tiny helper to drop a fixture into a temp dir.
func writeFile(t *testing.T, dir, rel, body string) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- RBAC: real AzGovViz column names must map correctly ---
func TestParseRBAC_RealColumns(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rbac.csv",
		"RoleDefinitionName,RoleAssignmentIdentityDisplayname,RoleAssignmentIdentityObjectType,RoleAssignmentId,RoleAssignmentScope\n"+
			"Owner,Alice Admin,User,ra-1,/subscriptions/sub-a\n"+
			"Reader,Audit Grp,Group,ra-2,/subscriptions/sub-b\n")
	ms, as, err := parseRBAC(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 2 {
		t.Fatalf("want 2 assignments, got %d", len(as))
	}
	if as[0].Ident != "ra-1" || as[0].Principal != "Alice Admin" || as[0].PrincipalType != "User" ||
		as[0].Role != "Owner" || as[0].Scope != "/subscriptions/sub-a" {
		t.Fatalf("row0 mismapped: %+v", as[0])
	}
	var count float64
	for _, m := range ms {
		if m.Category == "rbac" && m.Key == "count" {
			count = m.Value
		}
	}
	if count != 2 {
		t.Fatalf("rbac count want 2, got %v", count)
	}
}

// --- Policy compliance: aggregates + per-assignment status ---
func TestParsePolicyCompliance(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "pc.csv",
		"PolicyAssignmentName,PolicyDefinitionName,Category,Scope,ComplianceState,CompliantResources,NonCompliantResources\n"+
			"A,defA,Storage,/sub-a,Compliant,100,0\n"+
			"B,defB,Compute,/sub-a,NonCompliant,50,30\n")
	ms, fs, err := parsePolicyCompliance(p)
	if err != nil {
		t.Fatal(err)
	}
	get := func(k string) float64 {
		for _, m := range ms {
			if m.Key == k {
				return m.Value
			}
		}
		t.Fatalf("missing metric %s", k)
		return 0
	}
	if get("compliant_resources") != 150 || get("noncompliant_resources") != 30 {
		t.Fatalf("resource totals wrong: c=%v n=%v", get("compliant_resources"), get("noncompliant_resources"))
	}
	if get("noncompliant_assignments") != 1 {
		t.Fatalf("noncompliant assignments want 1, got %v", get("noncompliant_assignments"))
	}
	if len(fs) != 2 || fs[1].Status != "non_compliant" || fs[0].Status != "compliant" {
		t.Fatalf("findings status wrong: %+v", fs)
	}
}

// --- Maester: top-level counts win; version-as-object; severity from Tag ---
func TestParseMaester_RealShape(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "m.json", `{
      "Result":"Failed","TotalCount":10,"PassedCount":7,"FailedCount":3,"SkippedCount":0,
      "ExecutedAt":"2026-08-01T02:00:00Z","TenantName":"example",
      "CurrentVersion":{"Major":2,"Minor":2,"Build":0,"Revision":-1},
      "Tests":[
        {"Id":"MT.1","Title":"legacy auth blocked","Name":"MT.1","Result":"Failed","Block":"CA","Tag":["L1"]},
        {"Id":"MT.2","Title":"mfa","Name":"MT.2","Result":"Passed","Block":"CA","Tag":["L2"]}
      ]}`)
	ms, fs, meta, err := parseMaester(p)
	if err != nil {
		t.Fatal(err)
	}
	get := func(k string) float64 {
		for _, m := range ms {
			if m.Key == k {
				return m.Value
			}
		}
		return -1
	}
	// Top-level counts must override the 2-item Tests array.
	if get("passed") != 7 || get("failed") != 3 {
		t.Fatalf("top-level counts ignored: passed=%v failed=%v", get("passed"), get("failed"))
	}
	if meta.ToolVersion != "2.2.0" {
		t.Fatalf("version object not parsed, got %q", meta.ToolVersion)
	}
	if meta.CollectedAt.IsZero() || meta.Tenant != "example" {
		t.Fatalf("meta wrong: %+v", meta)
	}
	if fs[0].Severity != "High" { // L1 -> High
		t.Fatalf("severity from tag L1 want High, got %q", fs[0].Severity)
	}
	if fs[1].Severity != "Medium" { // L2 -> Medium
		t.Fatalf("severity from tag L2 want Medium, got %q", fs[1].Severity)
	}
}

// --- CA: real EntraExporter nests one file per object under subfolders ---
func TestParseCA_NestedDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "AccessPolicies/id-a/id-a.json",
		`{"id":"id-a","displayName":"MFA all","state":"enabled","grantControls":{"builtInControls":["mfa"]}}`)
	writeFile(t, dir, "AccessPolicies/id-b/id-b.json",
		`{"id":"id-b","displayName":"Report only","state":"enabledForReportingButNotEnforced"}`)
	ms, as, err := parseCA(filepath.Join(dir, "AccessPolicies"))
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 2 {
		t.Fatalf("want 2 CA policies from nested dirs, got %d", len(as))
	}
	get := func(k string) float64 {
		for _, m := range ms {
			if m.Key == k {
				return m.Value
			}
		}
		return -1
	}
	if get("total") != 2 || get("enabled") != 1 || get("report_only") != 1 {
		t.Fatalf("CA metrics wrong: %+v", ms)
	}
}

// --- CA: also accept a Graph {"value":[...]} envelope (single file) ---
func TestParseCA_Envelope(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ca.json",
		`{"value":[{"id":"x","displayName":"p","state":"enabled"}]}`)
	_, as, err := parseCA(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Ident != "x" {
		t.Fatalf("envelope not decoded: %+v", as)
	}
}

// --- Adapter discovery: the policy-column guard must skip *PolicyAssignments* ---
func TestDiscover_PolicyGuardAndClassification(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "AzGovViz_mg_RoleAssignments.csv",
		"RoleAssignmentId,RoleDefinitionName,RoleAssignmentScope\nra-1,Owner,/sub-a\n")
	// Decoy: has 'policy' in name but NO compliance columns -> must be ignored.
	writeFile(t, dir, "AzGovViz_mg_PolicyAssignments.csv",
		"PolicyAssignmentName,Effect\nA,Deny\n")
	// Real compliance CSV: has compliance columns -> must be chosen.
	writeFile(t, dir, "AzGovViz_mg_PolicyComplianceStates.csv",
		"PolicyAssignmentName,ComplianceState,CompliantResources,NonCompliantResources\nA,Compliant,10,0\n")
	writeFile(t, dir, "run-TestResults.json", `{"TotalCount":1,"PassedCount":1,"FailedCount":0,"Tests":[]}`)
	writeFile(t, dir, "EntraBackup/Identity/Conditional/AccessPolicies/i/i.json",
		`{"id":"i","displayName":"p","state":"enabled"}`)

	d, err := discover(dir, DefaultSpec())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(d.rbac) != "AzGovViz_mg_RoleAssignments.csv" {
		t.Fatalf("rbac not discovered: %q", d.rbac)
	}
	if filepath.Base(d.policy) != "AzGovViz_mg_PolicyComplianceStates.csv" {
		t.Fatalf("guard failed: policy=%q (should be ComplianceStates, not Assignments)", d.policy)
	}
	if filepath.Base(d.maester) != "run-TestResults.json" {
		t.Fatalf("maester not discovered: %q", d.maester)
	}
	if filepath.Base(d.caDir) != "AccessPolicies" {
		t.Fatalf("CA dir not discovered: %q", d.caDir)
	}
}

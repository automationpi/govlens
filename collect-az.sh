#!/usr/bin/env bash
# Real-tenant collector shim using the Azure CLI (no PowerShell needed).
# Emits azure-govlens' normalized run contract from a live, read-only az session.
# Covers what az can reach: RBAC + Conditional Access (+ policy compliance if
# Policy Insights has data). Maester's security tests need PowerShell and are
# out of scope for this shim.
set -euo pipefail

OUT="${1:-./realrun}"
TENANT_LABEL="${2:-example-sandbox}"
mkdir -p "$OUT/azgovviz" "$OUT/entraexporter"

echo "==> RBAC (az role assignment list)"
az role assignment list --all -o json > "$OUT/.roles.json"
python3 - "$OUT/.roles.json" "$OUT/azgovviz/rbac.csv" <<'PY'
import csv, json, sys
src, dst = sys.argv[1], sys.argv[2]
rows = json.load(open(src))
with open(dst, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["RoleAssignmentId","RoleDefinitionName","PrincipalType","PrincipalDisplayName","PrincipalId","Scope"])
    for r in rows:
        w.writerow([r.get("id",""), r.get("roleDefinitionName",""), r.get("principalType",""),
                    r.get("principalName",""), r.get("principalId",""), r.get("scope","")])
print(f"   {len(rows)} role assignments")
PY

echo "==> Conditional Access (Microsoft Graph)"
az rest --method get \
  --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' \
  -o json > "$OUT/entraexporter/ConditionalAccessPolicies.json" \
  && echo "   $(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["value"]))' "$OUT/entraexporter/ConditionalAccessPolicies.json")) policies" \
  || echo "   (CA not accessible — skipped)"

echo "==> Policy compliance (best effort)"
if az policy state summarize -o json > "$OUT/.policy.json" 2>/dev/null && \
   [ "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d.get("value",[])))' "$OUT/.policy.json" 2>/dev/null || echo 0)" != "0" ]; then
  python3 - "$OUT/.policy.json" "$OUT/azgovviz/policy_compliance.csv" <<'PY'
import csv, json, sys
d = json.load(open(sys.argv[1]))
with open(sys.argv[2], "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["PolicyAssignmentName","PolicyDefinitionName","Category","Scope","ComplianceState","CompliantResources","NonCompliantResources"])
    for v in d.get("value", []):
        res = v.get("results", {})
        comp = res.get("resourceDetails", [])
        c = next((x["count"] for x in comp if x.get("complianceState")=="Compliant"), 0)
        nc = res.get("nonCompliantResources", 0)
        w.writerow([v.get("policyAssignmentName","(assignment)"), "", "", v.get("policyAssignmentId",""),
                    "NonCompliant" if nc else "Compliant", c, nc])
print("   policy compliance written")
PY
else
  echo "   (no policy compliance data — skipped; provenance will omit it)"
fi

# Run identity.
python3 - "$OUT/manifest.json" "$TENANT_LABEL" <<'PY'
import json, sys, datetime
json.dump({"tenant": sys.argv[2],
           "collected_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")},
          open(sys.argv[1], "w"))
PY

rm -f "$OUT/.roles.json" "$OUT/.policy.json"
echo "==> Real run ready at $OUT"

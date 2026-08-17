#!/usr/bin/env bash
# Create a READ-ONLY service principal for the azure-govlens collectors.
# Run this while logged in as a PRIVILEGED account (can create apps, grant admin
# consent, and assign Reader at the management-group root):
#     az login   # as the privileged account
#     bash scripts/create-readonly-sp.sh --mg <mg-root-id> [--full] [--cert | --secret | \
#          --federated-issuer <url> --federated-subject <subj>]
#
# Everything it grants is read-only: Reader on ARM + *.Read.* Graph app permissions.
set -euo pipefail

APP_NAME="govlens-collector"
GRAPH_APP="00000003-0000-0000-c000-000000000000"
MG_ID=""
TIER="essential"          # or "full"
CRED="cert"               # cert | secret | federated
FED_ISSUER=""; FED_SUBJECT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --name) APP_NAME="$2"; shift 2;;
    --mg) MG_ID="$2"; shift 2;;
    --full) TIER="full"; shift;;
    --cert) CRED="cert"; shift;;
    --secret) CRED="secret"; shift;;
    --federated) CRED="federated"; shift;;
    --federated-issuer) CRED="federated"; FED_ISSUER="$2"; shift 2;;
    --federated-subject) FED_SUBJECT="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done
[ -n "$MG_ID" ] || { echo "ERROR: --mg <management-group-root-id> is required"; exit 1; }

ESSENTIAL="Directory.Read.All Policy.Read.All Policy.Read.ConditionalAccess RoleManagement.Read.All"
FULL_EXTRA="RoleManagement.Read.Directory UserAuthenticationMethod.Read.All Reports.Read.All AuditLog.Read.All \
Application.Read.All Group.Read.All User.Read.All IdentityRiskEvent.Read.All IdentityRiskyUser.Read.All \
SecurityEvents.Read.All Agreement.Read.All CrossTenantInformation.ReadBasic.All PrivilegedAccess.Read.AzureAD"
PERMS="$ESSENTIAL"; [ "$TIER" = "full" ] && PERMS="$ESSENTIAL $FULL_EXTRA"

echo "==> Creating app registration '$APP_NAME'"
APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad sp create --id "$APP_ID" >/dev/null 2>&1 || true
echo "   appId: $APP_ID"

echo "==> Resolving + adding read-only Graph application permissions ($TIER)"
ROLES=$(az ad sp show --id "$GRAPH_APP" --query "appRoles[].{v:value,id:id}" -o json)
for name in $PERMS; do
  pid=$(echo "$ROLES" | python3 -c "import json,sys;print(next((r['id'] for r in json.load(sys.stdin) if r['v']=='$name'),''))")
  [ -n "$pid" ] || { echo "   !! $name not found — skipping"; continue; }
  az ad app permission add --id "$APP_ID" --api "$GRAPH_APP" --api-permissions "$pid=Role" >/dev/null 2>&1
  echo "   + $name"
done

echo "==> Granting admin consent (needs Privileged Role Admin / Global Admin)"
sleep 10  # let the app propagate before consent
az ad app permission admin-consent --id "$APP_ID"

echo "==> Assigning Reader at the management-group root"
SP_OBJ=$(az ad sp show --id "$APP_ID" --query id -o tsv)
az role assignment create --assignee-object-id "$SP_OBJ" --assignee-principal-type ServicePrincipal \
  --role Reader --scope "/providers/Microsoft.Management/managementGroups/$MG_ID" >/dev/null
echo "   Reader @ mg/$MG_ID"

# Reader can't read Azure Policy compliance: policyStates/summarize is a
# PolicyInsights /action, and no read-only built-in role grants it. Create a
# minimal read-only custom role and assign it too.
echo "==> Creating + assigning 'GovLens Policy Reader' custom role (read-only policy compliance)"
POLICY_ROLE_JSON=$(cat <<JSON
{
  "Name": "GovLens Policy Reader",
  "IsCustom": true,
  "Description": "Read-only Azure Policy compliance states for the GovLens collector.",
  "Actions": [
    "Microsoft.PolicyInsights/policyStates/summarize/action",
    "Microsoft.PolicyInsights/policyStates/queryResults/action",
    "Microsoft.Authorization/policyAssignments/read",
    "Microsoft.Authorization/policyDefinitions/read",
    "Microsoft.Authorization/policySetDefinitions/read"
  ],
  "AssignableScopes": [ "/providers/Microsoft.Management/managementGroups/$MG_ID" ]
}
JSON
)
if ! az role definition list --name "GovLens Policy Reader" --query "[0].name" -o tsv 2>/dev/null | grep -q .; then
  az role definition create --role-definition "$POLICY_ROLE_JSON" >/dev/null && echo "   custom role created"
fi
# Assignment cascades from MG to subscriptions; propagation can take 5-15 min.
for i in 1 2 3 4 5 6; do
  az role assignment create --assignee-object-id "$SP_OBJ" --assignee-principal-type ServicePrincipal \
    --role "GovLens Policy Reader" --scope "/providers/Microsoft.Management/managementGroups/$MG_ID" -o none 2>/dev/null \
    && { echo "   GovLens Policy Reader @ mg/$MG_ID"; break; }
  sleep 15
done

echo "==> Credential ($CRED)"
case "$CRED" in
  cert)
    az ad app credential reset --id "$APP_ID" --create-cert --years 1 \
      --query '{appId:appId, tenant:tenant, certPath:fileWithCertAndPrivateKey}' -o json
    echo "   Keep the PEM safe; it is the private key. Connect with -CertificatePath."
    ;;
  secret)
    echo "   (client secrets are discouraged — prefer --cert or --federated)"
    az ad app credential reset --id "$APP_ID" --years 1 \
      --query '{appId:appId, tenant:tenant, secret:password}' -o json
    ;;
  federated)
    [ -n "$FED_ISSUER" ] && [ -n "$FED_SUBJECT" ] || {
      echo "   federated selected but --federated-issuer/--federated-subject not given."
      echo "   GitHub:  issuer https://token.actions.githubusercontent.com  subject repo:<org>/<repo>:ref:refs/heads/main"
      echo "   ADO:     issuer https://vstoken.dev.azure.com/<orgId>        subject sc://<org>/<project>/<serviceConnection>"
      exit 1; }
    az ad app federated-credential create --id "$APP_ID" --parameters "$(cat <<JSON
{ "name": "govlens-ci", "issuer": "$FED_ISSUER", "subject": "$FED_SUBJECT", "audiences": ["api://AzureADTokenExchange"] }
JSON
)"
    echo "   Federated credential added (no secret stored)."
    ;;
esac

echo
echo "==> DONE. appId=$APP_ID  tenant=$(az account show --query tenantId -o tsv)"
echo "   Collectors authenticate as this SP; GovLens app itself still needs NO Azure identity."

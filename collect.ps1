<#
.SYNOPSIS
  Run the three free collectors in-tenant and emit a raw run directory that
  `ingest -native` consumes. Scheduling/CI is intentionally NOT here — this is
  the unit a scheduler calls.

.NOTES
  Auth: run after authenticating as a READ-ONLY identity (federated/OIDC service
  principal recommended — no secret). Required access:
    - Azure ARM: Reader at the management-group root          (AzGovViz)
    - Microsoft Graph (application, read-only):               (Maester + EntraExporter)
        Policy.Read.All, Directory.Read.All,
        RoleManagement.Read.All, Reports.Read.All

  PII note: AzGovViz captures user DisplayName/SignInName for role assignments by
  default. Pass -DoNotIncludeResourceIdsAndScopesOnRBAC / the relevant AzGovViz
  switch if you must avoid storing that.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantName,
  [string]$ManagementGroupId,                        # required only for AzGovViz
  [switch]$SkipAzGovViz,                             # Graph-only run (Maester + EntraExporter)
  [string]$EntraType = "ConditionalAccess",          # EntraExporter -Type tag (Config = broader)
  [string]$OutRoot = "./raw-runs",
  [string]$AzGovVizScript = "./AzGovVizParallel.ps1",
  # Read-only service-principal auth (from scripts/create-readonly-sp.sh --cert).
  # When given, the script connects Az + Graph as the SP; otherwise it uses your
  # existing interactive context (and Maester will prompt if Graph isn't connected).
  [string]$AppId, [string]$CertPath, [string]$TenantId
)

$ErrorActionPreference = "Stop"

if ($AppId -and $CertPath) {
  if (-not $TenantId) { throw "-TenantId is required together with -AppId/-CertPath" }
  Write-Host "==> Connecting as read-only SP $AppId (certificate)"
  Connect-AzAccount -ServicePrincipal -ApplicationId $AppId -Tenant $TenantId -CertificatePath $CertPath | Out-Null
  # Graph needs an X509Certificate2 object; round-trip through PKCS#12 so the key handle is usable.
  $tmp  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($CertPath)
  $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($tmp.Export('Pkcs12'))
  Connect-MgGraph -ClientId $AppId -TenantId $TenantId -Certificate $cert -NoWelcome | Out-Null
}
$stamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH-mm-ssZ")
$runDir  = Join-Path $OutRoot "raw-$stamp"
$azDir   = Join-Path $runDir  "azgovviz"
$mtDir   = Join-Path $runDir  "maester"
$eeDir   = Join-Path $runDir  "entra"
New-Item -ItemType Directory -Force -Path $azDir,$mtDir,$eeDir | Out-Null

if ($SkipAzGovViz) {
  Write-Host "==> AzGovViz SKIPPED (-SkipAzGovViz): Graph-only run"
} elseif (-not $ManagementGroupId) {
  Write-Host "==> AzGovViz SKIPPED: no -ManagementGroupId given"
} else {
  Write-Host "==> AzGovViz (policy + RBAC) — needs an Az context (Connect-AzAccount)"
  # AzGovViz writes its CSVs under -OutputPath; the adapter discovers them by name.
  & $AzGovVizScript -ManagementGroupId $ManagementGroupId -OutputPath $azDir 2>&1 | Out-Null
}

Write-Host "==> Maester (Entra/M365 security tests)"
Import-Module Maester -ErrorAction Stop          # needs Pester 5+/6 (see scripts/bootstrap-modules.ps1)
# Maester 2.x ships its tests separately; scaffold them once into the run dir.
$mtTests = Join-Path $runDir "maester-tests"
if (-not (Test-Path (Join-Path $mtTests "tests"))) { Install-MaesterTests $mtTests | Out-Null }
# Reuse an existing Graph connection if present, else connect (read-only).
if (-not (Get-MgContext -ErrorAction SilentlyContinue)) { Connect-Maester | Out-Null }
# Maester 2.x uses -OutputJsonFile (there is no -OutputJson switch).
Invoke-Maester -Path $mtTests -OutputJsonFile (Join-Path $mtDir "test-results.json") | Out-Null

Write-Host "==> EntraExporter (Conditional Access + identity config)"
Import-Module EntraExporter -ErrorAction Stop
# Writes one JSON per object under $eeDir (…/Identity/Conditional/AccessPolicies/).
# 'ConditionalAccess' is a lean, targeted export; use -EntraType Config for the full config.
Export-Entra -Path $eeDir -Type $EntraType | Out-Null

# Stamp run identity so ingestion has an authoritative collected_at even if a
# collector that carries its own timestamp (Maester) failed to run.
@{
  tenant       = $TenantName
  collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json | Set-Content -Path (Join-Path $runDir "manifest.json")

Write-Host "==> Raw run ready: $runDir"
Write-Host "    Ingest with:  ingest -dsn <dsn> -native $runDir"

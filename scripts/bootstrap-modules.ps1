<#
  Run INSIDE pwsh after PowerShell is installed:  pwsh -File scripts/bootstrap-modules.ps1
  Installs the free collectors' modules to the CurrentUser scope (no admin needed)
  and clones AzGovViz (a script, not a gallery module).
#>
$ErrorActionPreference = "Stop"

$hasPSResource = [bool](Get-Command Install-PSResource -ErrorAction SilentlyContinue)

if ($hasPSResource) {
  # First-run fix: PSResourceGet's store file may not exist yet, which makes
  # Set-PSResourceRepository fail during parameter binding. Create the store dir
  # and let the default PSGallery register, then mark it trusted.
  $store = Join-Path $HOME ".local/share/PSResourceGet"
  New-Item -ItemType Directory -Force -Path $store | Out-Null
  if (-not (Get-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
    try { Register-PSResourceRepository -PSGallery -Trusted -ErrorAction Stop } catch {}
  }
  try { Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction Stop } catch {}
} else {
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

function Install-Mod($name) {
  Write-Host "==> $name"
  if ($script:hasPSResource) {
    Install-PSResource -Name $name -Scope CurrentUser -TrustRepository
  } else {
    Install-Module -Name $name -Scope CurrentUser -Force -AllowClobber
  }
}

# Maester + EntraExporter are the Entra collectors. Az.* + Microsoft.Graph cover
# AzGovViz's needs. (Az is large; Az.Accounts/Az.Resources/Az.ResourceGraph are
# the minimum AzGovViz uses — install full Az only if you want everything.)
Install-Mod Pester          # Maester 2.x requires Pester 5+ (a stale Pester 4.x will break its import)
Install-Mod Maester
Install-Mod EntraExporter
Install-Mod Az.Accounts
Install-Mod Az.Resources
Install-Mod Az.ResourceGraph
Install-Mod Microsoft.Graph.Authentication
Install-Mod AzAPICall   # AzGovViz dependency; if absent, AzGovViz prompts to install it and hangs headless

# AzGovViz ships as a script; clone it next to this repo.
$azgov = Join-Path (Split-Path $PSScriptRoot -Parent) "third_party/Azure-Governance-Visualizer"
if (-not (Test-Path $azgov)) {
  Write-Host "==> cloning AzGovViz"
  git clone --depth 1 https://github.com/Azure/Azure-Governance-Visualizer.git $azgov
}
Write-Host "`nDone. AzGovViz script: $azgov/pwsh/AzGovVizParallel.ps1"
Write-Host "Next: authenticate (Connect-AzAccount; Connect-MgGraph -Scopes Policy.Read.All,Directory.Read.All,RoleManagement.Read.All,Reports.Read.All)"
Write-Host "Then: pwsh -File collect.ps1 -ManagementGroupId <mg> -TenantName <name> -AzGovVizScript $azgov/pwsh/AzGovVizParallel.ps1"

<#
  Connect Az + Microsoft Graph as the read-only collector SP using its certificate.
  Dot-source or run inside a pwsh session, then run collectors in the same session:
      . ./scripts/connect-sp.ps1 -AppId <appId> -TenantId <tid> -CertPath <pem>
  (collect.ps1 can also take -AppId/-CertPath/-TenantId and connect itself.)
#>
param(
  [Parameter(Mandatory)][string]$AppId,
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$CertPath   # PEM from `az ad app credential reset --create-cert`
)
$ErrorActionPreference = "Stop"

Connect-AzAccount -ServicePrincipal -ApplicationId $AppId -Tenant $TenantId -CertificatePath $CertPath | Out-Null

$tmp  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($CertPath)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($tmp.Export('Pkcs12'))
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -Certificate $cert -NoWelcome | Out-Null

Write-Host "Connected as SP $AppId (Az + Graph, read-only)."

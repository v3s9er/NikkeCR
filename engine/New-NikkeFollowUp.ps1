#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$InventoryPath,[string]$PreviousInventoryPath='',[string]$OutputRoot=(Join-Path $env:LOCALAPPDATA 'NikkeRecovery\FollowUp'))
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.FollowUp.psm1') -DisableNameChecking
function Read-Inventory([string]$Path){
    $Path=Get-CanonicalPath $Path;Assert-NoReparse $Path
    if((Get-Item -LiteralPath $Path).Length -gt 32MB){throw 'Inventory JSON exceeds 32 MiB limit'}
    $r=Get-Content -Encoding UTF8 -LiteralPath $Path -Raw | ConvertFrom-Json
    if(-not $r.PSObject.Properties['InstalledPrograms'] -or -not $r.PSObject.Properties['LaunchRelationships']){throw 'Not a post-recovery inventory'}
    return $r
}
$current=Read-Inventory $InventoryPath
$previous=$null;if($PreviousInventoryPath){$previous=Read-Inventory $PreviousInventoryPath}
$OutputRoot=Get-CanonicalPath $OutputRoot
$dir=Join-Path $OutputRoot ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
New-ProtectedDirectory $dir ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
Save-Json (Join-Path $dir 'program-recovery-plan.json') (New-ProgramRecoveryPlan $current)
if($null -ne $previous){Save-Json (Join-Path $dir 'snapshot-differences.json') (Compare-RecoveryInventories $previous $current)}
Write-Output ('Follow-up reports: '+$dir)
Write-Output 'Reports contain private paths and commands. No application, setting or credential was modified; no clean-host verdict is issued.'

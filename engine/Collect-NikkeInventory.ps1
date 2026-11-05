#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$TargetSid,[Parameter(Mandatory=$true)][string]$TargetProfile,[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.PostRecovery.psm1') -DisableNameChecking
$OutputDirectory=Get-CanonicalPath $OutputDirectory;Assert-NoReparse $OutputDirectory
if(-not(Test-Path -LiteralPath $OutputDirectory -PathType Container)){throw 'Existing protected output directory required'}
$r=Get-PostRecoveryInventory -TargetSid $TargetSid -TargetProfile $TargetProfile -PartialPath (Join-Path $OutputDirectory 'inventory-partial.json')
Save-Json (Join-Path $OutputDirectory 'inventory-worker.json') $r

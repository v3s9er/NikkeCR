#requires -Version 5.1
[CmdletBinding()]param([ValidateSet('Audit','Plan','Apply','Verify')][string]$Mode='Audit',[string]$TargetProfile=$env:USERPROFILE,[string]$OutputRoot='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Test-NikkePackage.ps1')
Assert-NikkePackage $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -Force -DisableNameChecking
$TargetProfile=Get-CanonicalPath $TargetProfile
if (-not $OutputRoot) {$OutputRoot=Join-Path $env:LOCALAPPDATA 'NikkeRecovery\Evidence'}
$OutputRoot=Get-CanonicalPath $OutputRoot
$runToken=[guid]::NewGuid().ToString('N')
$admin=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$entryPoint=Join-Path $PSScriptRoot 'Invoke-NikkeRecovery.ps1'
if ($Mode -eq 'Apply' -and -not $admin) {
    # Pass the original profile explicitly so an alternate administrator's HKCU is never repaired by mistake.
    $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$entryPoint+'"'),'-Mode','Apply','-TargetProfile',('"'+$TargetProfile+'"'),'-OutputRoot',('"'+$OutputRoot+'"'),'-RunToken',$runToken)
    Write-Host 'Requesting Windows elevation for the reviewed recovery actions. No reboot or application termination is automatic.'
    try {$child=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru}
    catch {
        $failureCode=Get-ElevationFailureCode $_.Exception
        if ($failureCode -eq 1223) {Write-Warning 'Windows UAC was cancelled. No recovery process started. Existing containment was not changed.'}
        else {Write-Warning ('Windows could not start the recovery process: '+$_.Exception.Message)}
        exit $failureCode
    }
    $runs=@(Get-ChildItem -LiteralPath $OutputRoot -Directory -Filter ('*-'+$runToken) -ErrorAction SilentlyContinue)
    $receipt=$null
    if ($runs.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $runs[0].FullName 'summary.json'))) {$receipt=Get-Content -Encoding UTF8 -Raw -LiteralPath (Join-Path $runs[0].FullName 'summary.json') | ConvertFrom-Json}
    if ($null -eq $receipt -or $receipt.RunToken -ne $runToken -or $receipt.TargetProfile -ine $TargetProfile) {Write-Warning ('No matching completion report was produced. Child exit code: '+$child.ExitCode);exit 1}
    Write-Host ('Result: '+$receipt.Verdict)
    Write-Host ('Completed actions: '+@($receipt.Outcomes | Where-Object Status -eq 'Completed').Count)
    Write-Host ('Failed actions: '+@($receipt.Outcomes | Where-Object Status -eq 'Failed').Count)
    Write-Host ('Report: '+(Join-Path $runs[0].FullName 'REPORT.txt'))
    if ([int]$receipt.ExitCode -ne [int]$child.ExitCode) {Write-Warning 'Reported status and process exit disagree; inspect the saved evidence.';exit 1}
    exit $child.ExitCode
} else {
    $parameters=@{Mode=$Mode;TargetProfile=$TargetProfile;OutputRoot=$OutputRoot;RunToken=$runToken}
    & $entryPoint @parameters
    exit $LASTEXITCODE
}

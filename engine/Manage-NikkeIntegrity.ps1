#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [ValidateSet('Baseline','Plan','Apply')][string]$Mode='Plan',
    [string]$PackagePath,[string]$PackageSHA256,[string]$ProgramName,[string]$ProgramVersion,[string]$SourceUri,[string]$ArchivePrefix='',
    [string]$BaselinePath,[string]$BaselineSHA256,[string]$TargetRoot,
    [string]$PlanPath,[string]$PlanSHA256,[string[]]$RelativePath=@(),
    [string]$OutputRoot=(Join-Path $env:LOCALAPPDATA 'NikkeRecovery\Integrity')
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Test-NikkePackage.ps1');Assert-NikkePackage $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Integrity.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
$OutputRoot=Get-CanonicalPath $OutputRoot
if($Mode -eq 'Apply'){
    $baseline=Read-NikkePinnedJson $BaselinePath $BaselineSHA256
    $plan=Read-NikkePinnedJson $PlanPath $PlanSHA256
    if($plan.BaselineSHA256 -ine $BaselineSHA256){throw 'Plan belongs to another baseline'}
    if($PSCmdlet.ShouldProcess($plan.TargetRoot,('Replace explicitly selected package binaries: '+($RelativePath -join ', ')))){
        $result=Invoke-NikkePinnedRepair $plan $baseline $PackagePath $RelativePath $OutputRoot
        $result|ConvertTo-Json -Depth 8
        if($result.Failed -or $result.Completed -ne $result.Selected){exit 2}
    }
    exit 0
}
if($Mode -eq 'Baseline'){$value=New-NikkeVendorBaseline $PackagePath $PackageSHA256 $ProgramName $ProgramVersion $SourceUri $ArchivePrefix;$name='baseline.json'}
else{$baseline=Read-NikkePinnedJson $BaselinePath $BaselineSHA256;$value=New-NikkeIntegrityPlan $baseline $BaselineSHA256 $TargetRoot;$name='integrity-plan.json'}
$dir=Join-Path $OutputRoot ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
New-ProtectedDirectory $dir ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
$path=Join-Path $dir $name;Save-Json $path $value
[pscustomobject]@{Mode=$Mode;Report=$path;SHA256=(Get-NikkeFileDigest $path).SHA256;WholeHostCleanClaim=$false}|ConvertTo-Json

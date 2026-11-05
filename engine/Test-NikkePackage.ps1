# Shared preflight for every new entry point. Hashes are integrity checks, not publisher authentication.
function Assert-NikkePackage([string]$Root=$PSScriptRoot) {
    $manifestPath=Join-Path $Root 'PACKAGE-SHA256.json'
    if(-not(Test-Path -LiteralPath $manifestPath)){throw 'Package manifest missing'}
    $manifest=Get-Content -Encoding UTF8 -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    $required=@('Collect-NikkeInventory.ps1','Invoke-NikkeRecovery.ps1','LICENSE','New-CleanerTestSandbox.ps1','New-NikkeFollowUp.ps1','NikkeRecovery.Core.psm1','NikkeRecovery.FollowUp.psm1','NikkeRecovery.Lua.psm1','NikkeRecovery.PostRecovery.psm1','README.md','README-ko.md','Run-Audit.cmd','Run-Repair.cmd','Run-Verify.cmd','Start-NikkeRecovery.ps1','Test-NikkeExtended.ps1','Test-NikkeRecovery.ps1','Test-SandboxIntegration.ps1','VALIDATION.md','Test-NikkePackage.ps1','NikkeRecovery.Integrity.psm1','Manage-NikkeIntegrity.ps1','NikkeRecovery.Aftercare.psm1','Invoke-NikkeAftercare.ps1','Register-NikkeAftercare.ps1','Run-Aftercare.cmd','Test-NikkeAftercare.ps1')
    if($manifest.Version -ne '0.3.1-preview' -or @($manifest.Files).Count -ne $required.Count -or @($manifest.Files.File|Sort-Object -Unique).Count -ne $required.Count -or @(Compare-Object ($required|Sort-Object) (@($manifest.Files.File)|Sort-Object)).Count){throw 'Invalid or incomplete package manifest'}
    foreach($entry in $manifest.Files){
        if($entry.SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $entry.File -notin $required){throw 'Invalid package entry'}
        $path=Join-Path $Root $entry.File
        if(-not(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $entry.SHA256){throw ('Package integrity mismatch: '+$entry.File)}
    }
}

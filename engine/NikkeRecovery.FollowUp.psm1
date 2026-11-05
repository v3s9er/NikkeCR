# Evidence-based follow-up planning and snapshot comparison. No repair commands are executed.
Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
function Get-RecoveryProperty($Object,[string]$Name,$Default=$null) {
    if($null -ne $Object -and $Object.PSObject.Properties[$Name]){return $Object.$Name}
    return $Default
}
function New-ProgramRecoveryPlan($Inventory) {
    $programs=@(Get-RecoveryProperty $Inventory 'InstalledPrograms' @())
    $links=@(Get-RecoveryProperty $Inventory 'LaunchRelationships' @())
    $known=@(Get-RecoveryProperty $Inventory 'ConfirmedReferences' @())
    $roots=New-Object 'Collections.Generic.List[object]'
    foreach($p in $programs){
        $root=$null
        try{if($p.Location){$candidate=Get-CanonicalPath $p.Location;if($candidate.Length -gt 3){$root=$candidate}}}catch{}
        $roots.Add([pscustomobject]@{Program=$p;Root=$root})
    }
    $rows=New-Object 'Collections.Generic.List[object]'
    foreach($entry in $roots){
        $related=@();$hits=@();$overlap=@()
        if($entry.Root){
            $related=@($links | Where-Object {$_.FilePath -and (Test-PathWithin $_.FilePath $entry.Root)})
            $hits=@($known | Where-Object {$_.Path -and (Test-PathWithin $_.Path $entry.Root)})
            $overlap=@($roots | Where-Object {$_.Program.RegistryPath -cne $entry.Program.RegistryPath -and $_.Root -and ($_.Root -ieq $entry.Root -or (Test-PathWithin $_.Root $entry.Root) -or (Test-PathWithin $entry.Root $_.Root))})
        }
        $status='NotIntegrityVerified';$next='Obtain a trusted vendor baseline and verify executable files, dependencies and configuration.'
        if($hits.Count){$status='IncidentReferenceNeedsReview';$next='Preserve the referenced files and settings; review the evidence, then repair or reinstall the affected component from a verified vendor source.'}
        $rows.Add([pscustomobject]@{Name=$entry.Program.Name;Version=$entry.Program.Version;Publisher=$entry.Program.Publisher;RegistryPath=$entry.Program.RegistryPath;InstallRoot=$entry.Root;RootAssociation=(@{0='Path association only; ownership is unverified';1='Overlapping registered roots; association is ambiguous'}[[int]($overlap.Count -gt 0)]);RelatedLaunchReferences=$related;KnownIncidentReferences=$hits;Status=$status;TrustedBaselineVerified=$false;AutomaticRepair=$false;NextStep=$next})
    }
    $unassigned=@($links | Where-Object {
        $path=$_.FilePath;$matched=$false
        if($path){foreach($entry in $roots){if($entry.Root -and (Test-PathWithin $path $entry.Root)){$matched=$true;break}}}
        -not $matched
    })
    return [pscustomobject]@{At=(Get-Date -Format o);ReadOnly=$true;WholeHostCleanClaim=$false;ProgramCount=$rows.Count;Programs=$rows.ToArray();UnassignedLaunchReferences=$unassigned;InventoryCompleted=[bool](Get-RecoveryProperty $Inventory 'WorkerCompleted' $false);InventoryErrors=@(Get-RecoveryProperty $Inventory 'Errors' @());Coverage=(Get-RecoveryProperty $Inventory 'Coverage');RequiredFollowUp=@('Resolve unknown persistence and unexamined files before concluding recovery.','Verify suspect application components against signed vendor packages or a trusted pre-incident baseline; do not run repair commands merely because they appear in the registry.','For confirmed Windows component corruption, preserve findings and use supported Windows servicing tools; this inventory does not establish OS integrity.','After saving work and restarting affected applications or Windows, collect another inventory and compare for recurrence.','Revoke exposed sessions and rotate credentials from a trusted device; local cleanup cannot revoke stolen credentials.');Limitations=@('Registered programs are not a complete inventory of portable apps, MSIX apps, plugins or user scripts.','Install-directory association does not establish who created a file or whether it is malicious.','Absence of a matching incident reference is never a clean or repaired verdict.')}
}
function Compare-RecoveryRows($Before,$After,[string[]]$KeyFields,[string[]]$ValueFields,[string]$Area) {
    $left=@{};$right=@{}
    foreach($side in @(@{Rows=@($Before);Map=$left},@{Rows=@($After);Map=$right})){
        foreach($row in $side.Rows){
            $key=ConvertTo-Json -Compress -InputObject @($KeyFields | ForEach-Object {Get-RecoveryProperty $row $_})
            $value=[ordered]@{};foreach($field in $ValueFields){$value[$field]=Get-RecoveryProperty $row $field}
            $encoded=ConvertTo-Json -Compress -Depth 8 -InputObject $value
            if(-not $side.Map.ContainsKey($key)){$side.Map[$key]=@()}
            $side.Map[$key]+=$encoded
        }
    }
    foreach($key in @(@($left.Keys)+@($right.Keys) | Sort-Object -Unique)){
        $old=@();$new=@();if($left.ContainsKey($key)){$old=@($left[$key] | Sort-Object)};if($right.ContainsKey($key)){$new=@($right[$key] | Sort-Object)}
        if(($old -join "`n") -ceq ($new -join "`n")){continue}
        $kind='Changed';if(-not $left.ContainsKey($key)){$kind='Added'}elseif(-not $right.ContainsKey($key)){$kind='AbsentFromLaterSnapshot'}
        [pscustomobject]@{Area=$Area;Change=$kind;Identity=($key | ConvertFrom-Json);Before=@($old | ForEach-Object {$_ | ConvertFrom-Json});After=@($new | ForEach-Object {$_ | ConvertFrom-Json});Interpretation='Observed snapshot difference; not proof of malware, removal, or repair. Missing data may reflect incomplete coverage.'}
    }
}
function Compare-RecoveryInventories($Before,$After) {
    $changes=@(Compare-RecoveryRows @(Get-RecoveryProperty $Before 'LaunchRelationships' @()) @(Get-RecoveryProperty $After 'LaunchRelationships' @()) @('Kind','Source','Name') @('Command','Arguments','FilePath') 'LaunchReference')
    $changes+=@(Compare-RecoveryRows @(Get-RecoveryProperty $Before 'ReferencedFiles' @()) @(Get-RecoveryProperty $After 'ReferencedFiles' @()) @('Path') @('SHA256','Disposition') 'ReferencedFile')
    $changes+=@(Compare-RecoveryRows @(Get-RecoveryProperty $Before 'BrowserPolicies' @()) @(Get-RecoveryProperty $After 'BrowserPolicies' @()) @('Path','Name') @('Value') 'BrowserPolicy')
    $changes+=@(Compare-RecoveryRows @(Get-RecoveryProperty $Before 'InstalledPrograms' @()) @(Get-RecoveryProperty $After 'InstalledPrograms' @()) @('RegistryPath') @('Name','Version','Publisher','Location') 'ProgramRegistration')
    return [pscustomobject]@{At=(Get-Date -Format o);ReadOnly=$true;WholeHostCleanClaim=$false;TrustedBaselineProvided=$false;BeforeInventoryCompleted=[bool](Get-RecoveryProperty $Before 'WorkerCompleted' $false);AfterInventoryCompleted=[bool](Get-RecoveryProperty $After 'WorkerCompleted' $false);Changes=$changes;LaterIncidentReferences=@(Get-RecoveryProperty $After 'ConfirmedReferences' @());Limitations=@('Snapshots can both contain compromise and are not trusted baselines.','No differences does not establish integrity or absence of recurrence.','Absent rows may be caused by permissions, time limits or coverage differences; no repair is inferred.')}
}
Export-ModuleMember -Function New-ProgramRecoveryPlan,Compare-RecoveryInventories

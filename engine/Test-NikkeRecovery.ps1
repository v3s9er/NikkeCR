#requires -Version 5.1
[CmdletBinding()]param([string]$OutputRoot=$env:TEMP)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -Force -DisableNameChecking
$fixture=Join-Path $OutputRoot ('NikkeRecoveryTests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$results=New-Object 'Collections.Generic.List[object]'
function Check([string]$Name,[scriptblock]$Body) {
    try {& $Body;$results.Add([pscustomobject]@{Name=$Name;Passed=$true});Write-Host ('PASS '+$Name)}
    catch {$results.Add([pscustomobject]@{Name=$Name;Passed=$false;Error=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}
}
function Assert($Condition,[string]$Message='Assertion failed') {if (-not $Condition) {throw $Message}}
function Must-Throw([scriptblock]$Body) {$caught=$false;try {& $Body | Out-Null} catch {$caught=$true};Assert $caught 'Expected refusal'}
$profile=Join-Path $fixture 'Profile';$preserved=Join-Path $fixture 'Preserved'
New-Item -ItemType Directory -Path $profile,$preserved | Out-Null
Check 'Sibling-prefix path does not pass containment boundary' {Assert (-not (Test-PathWithin ($profile+'-other\x') $profile))}
Check 'Traversal is normalized and rejected at boundary' {Assert (-not (Test-PathWithin ($profile+'\..\outside.bin') $profile))}
Check 'UNC path refused' {Must-Throw {Get-CanonicalPath '\\server\share\x'}}
Check 'Alternate data stream refused' {Must-Throw {Get-CanonicalPath ($profile+'\x:stream')}}
Check 'Quoted/control-character paths cannot alter elevation arguments' {Must-Throw {Get-CanonicalPath ($profile+'\x" -OtherArgument')};Must-Throw {Get-CanonicalPath ($profile+"`r`nx")}}
Check 'Relative and root-equal paths refused as children' {Must-Throw {Get-CanonicalPath 'relative\x'};Assert (-not (Test-PathWithin $profile $profile))}
Check 'A failed repair action returns a non-success exit status' {Assert ((Get-RecoveryExitCode @([pscustomobject]@{Status='Completed'},[pscustomobject]@{Status='Failed'})) -eq 2)}
Check 'An unapproved changed action reports incomplete repair' {Assert ((Get-RecoveryExitCode @([pscustomobject]@{Status='NotApplied'})) -eq 2);Assert ((Get-RecoveryExitCode @([pscustomobject]@{Status='NotApplied'}) $true) -eq 0)}
Check 'Reviewed DLL approval is bound to the detected hash' {
    $hash='a'*64;$now=[pscustomobject]@{Kind='QuarantineDll';Target='C:\Fixture\incident.dll';Extra=[pscustomobject]@{SHA256=$hash;Verdict='Confirmed'}}
    $old=([pscustomobject]@{Kind='QuarantineDll';Target=$now.Target;Extra=[pscustomobject]@{SHA256=$hash;Verdict='Confirmed'}}|ConvertTo-Json -Depth 5|ConvertFrom-Json)
    Assert (Test-ApprovedActionMatch $now $old)
    $now.Extra.SHA256='b'*64;Assert (-not (Test-ApprovedActionMatch $now $old))
    $now.Extra.SHA256=$hash;$now.Extra.Verdict='Review';Assert (-not (Test-ApprovedActionMatch $now $old))
}
Check 'Reviewed COM approval is bound to the detected value' {
    $now=[pscustomobject]@{Kind='RemoveUserOverride';Target='Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}';Extra=[pscustomobject]@{Exists=$true;UnexpectedSubkeys=$false;Disposition='MatchedIncidentOverride';DefaultValue='C:\Fixture\incident.dll'}}
    $old=([pscustomobject]@{Kind=$now.Kind;Target=$now.Target;Extra=[pscustomobject]@{Exists=$true;UnexpectedSubkeys=$false;Disposition=$now.Extra.Disposition;DefaultValue=$now.Extra.DefaultValue}}|ConvertTo-Json -Depth 5|ConvertFrom-Json)
    Assert (Test-ApprovedActionMatch $now $old)
    $now.Extra.DefaultValue='C:\Fixture\other.dll';Assert (-not (Test-ApprovedActionMatch $now $old))
    $now.Extra.DefaultValue=$old.Extra.DefaultValue;$now.Extra.UnexpectedSubkeys=$true;Assert (-not (Test-ApprovedActionMatch $now $old))
}
Check 'Reviewed containment actions remain approved only for the same target' {
    foreach($kind in @('BlockC2','BlockDomains','IsolateCache')){
        $now=[pscustomobject]@{Kind=$kind;Target='C:\Fixture\target';Extra=$null}
        $old=$now|ConvertTo-Json -Depth 5|ConvertFrom-Json
        Assert (Test-ApprovedActionMatch $now $old)
        $old.Target='C:\Fixture\other';Assert (-not (Test-ApprovedActionMatch $now $old))
    }
    $now=[pscustomobject]@{Kind='BlockLauncher';Target='C:\Fixture\launcher.exe';Extra='Outbound'}
    $old=$now|ConvertTo-Json -Depth 5|ConvertFrom-Json
    Assert (Test-ApprovedActionMatch $now $old)
    $old.Extra='Inbound';Assert (-not (Test-ApprovedActionMatch $now $old))
}
Check 'Completed or no-op runs have completion status without a clean-host claim' {Assert ((Get-RecoveryExitCode @()) -eq 0);Assert ((Get-RecoveryExitCode @([pscustomobject]@{Status='Completed'})) -eq 0)}
Check 'Windows UAC cancellation is distinguished from a generic failure' {Assert ((Get-ElevationFailureCode ([ComponentModel.Win32Exception]::new(1223))) -eq 1223);Assert ((Get-ElevationFailureCode ([Exception]::new('fixture'))) -eq 1)}
Check 'Standard NIKKE launcher root is recognized' {$dir=Join-Path $fixture 'StandardLauncher';New-Item -ItemType Directory -Path $dir | Out-Null;[IO.File]::WriteAllText((Join-Path $dir 'nikke_launcher.exe'),'INERT FIXTURE');Assert (@(Get-KnownLauncherExecutables $dir).Count -eq 1)}
Check 'Google Play NIKKE launcher root is recognized' {$dir=Join-Path $fixture 'GoogleLauncher';New-Item -ItemType Directory -Path $dir | Out-Null;[IO.File]::WriteAllText((Join-Path $dir 'nikke_launcher_google.exe'),'INERT FIXTURE');Assert (@(Get-KnownLauncherExecutables $dir).Count -eq 1)}
Check 'Unrelated executable does not qualify a launcher root' {$dir=Join-Path $fixture 'Unrelated';New-Item -ItemType Directory -Path $dir | Out-Null;[IO.File]::WriteAllText((Join-Path $dir 'Assistant.exe'),'INERT FIXTURE');Assert (@(Get-KnownLauncherExecutables $dir).Count -eq 0)}
$dllDir=Join-Path $profile ('AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\'+('a'*64))
New-Item -ItemType Directory -Path $dllDir -Force | Out-Null
$candidate=Join-Path $dllDir 'platform_experience_helper.dll'
# Inert synthetic bytes only: a minimal identification header and plain strings, no executable code.
$bytes=New-Object byte[] 2048;$bytes[0]=0x4d;$bytes[1]=0x5a;[BitConverter]::GetBytes([int]128).CopyTo($bytes,0x3c);$bytes[128]=0x50;$bytes[129]=0x45;[BitConverter]::GetBytes([uint16]0x2000).CopyTo($bytes,150)
$markers='analytics.insightjs.com/px/ Debugger.paused Debugger.scriptParsed Runtime.callFunctionOn WinHttpSendRequest'
[Text.Encoding]::ASCII.GetBytes($markers).CopyTo($bytes,256);[IO.File]::WriteAllBytes($candidate,$bytes)
Check 'Combined variant heuristic detects inert positive fixture' {Assert ((Get-IncidentDllVerdict $candidate $profile).Verdict -eq 'StrongMatch')}
$fake=Join-Path $profile 'platform_experience_helper.dll';[IO.File]::WriteAllBytes($fake,$bytes)
Check 'Matching strings outside incident location do not authorize quarantine' {Assert ((Get-IncidentDllVerdict $fake $profile).Verdict -eq 'Review')}
Check 'Normal Chrome helper is not identified by directory name alone' {
    $normal=Join-Path (Split-Path $dllDir -Parent) 'platform_experience_helper.exe';[IO.File]::WriteAllText($normal,('normal fixture '*20));Assert ((Get-IncidentDllVerdict $normal $profile).Verdict -eq 'Review')
}
Check 'Incomplete marker set retained for review' {
    $original=[IO.File]::ReadAllBytes($candidate);$altered=[byte[]]$original.Clone();$altered[256]=0x58;[IO.File]::WriteAllBytes($candidate,$altered)
    try {Assert ((Get-IncidentDllVerdict $candidate $profile).Verdict -eq 'Review')} finally {[IO.File]::WriteAllBytes($candidate,$original)}
}
$key='Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
$verdict=Get-IncidentDllVerdict $candidate $profile
Check 'Exact correlated per-user COM override is removable' {Assert ((Get-RegistryDisposition $key $true $candidate @($verdict)) -eq 'MatchedIncidentOverride')}
Check 'HKLM COM key is never removable' {Assert ((Get-RegistryDisposition ($key.Replace('HKEY_USERS\S-1-5-21-1-2-3-1001','HKEY_LOCAL_MACHINE')) $true $candidate @($verdict)) -eq 'Review')}
Check 'Unknown COM target is retained' {Assert ((Get-RegistryDisposition $key $true 'C:\Windows\System32\wpc.dll' @($verdict)) -eq 'Review')}
Check 'Unexpected COM subkeys force manual review' {Assert ((Get-RegistryDisposition $key $true $candidate @($verdict) $true) -eq 'Review')}
Check 'Empty known per-user override can be removed without touching HKLM' {Assert ((Get-RegistryDisposition $key $true '' @()) -eq 'EmptyIncidentOverride')}
Check 'Commented hosts entry is not mistaken for a block' {Assert (-not (Test-HostsBlocked '# 0.0.0.0 insightjs.com' 'insightjs.com'))}
Check 'Hosts modification preserves every existing byte and is idempotent' {
    $original=[Text.Encoding]::UTF8.GetBytes("# keep`r`n192.0.2.2 example.invalid`r`n")
    $updated=Add-HostsBlockBytes $original @('insightjs.com','insightjs.org')
    Assert ([Convert]::ToBase64String($updated[0..($original.Length-1)]) -eq [Convert]::ToBase64String($original))
    $second=Add-HostsBlockBytes $updated @('insightjs.com','insightjs.org');Assert ([Convert]::ToBase64String($second) -eq [Convert]::ToBase64String($updated))
}
Check 'UTF-16 hosts remains UTF-16 and preserves original prefix' {
    $original=[byte[]]([Text.Encoding]::Unicode.GetPreamble()+[Text.Encoding]::Unicode.GetBytes("# keep`r`n"))
    $updated=Add-HostsBlockBytes $original @('insightjs.com');Assert (Test-HostsBlocked ([Text.Encoding]::Unicode.GetString($updated)) 'insightjs.com');Assert ($updated[0] -eq 255 -and $updated[1] -eq 254)
}
Check 'Evidence copy never overwrites an existing destination' {
    $dest=Join-Path $preserved 'exists.evidence';[IO.File]::WriteAllText($dest,'KEEP');Must-Throw {Copy-VerifiedEvidence $candidate $dest $verdict.SHA256};Assert ([IO.File]::ReadAllText($dest) -eq 'KEEP');Assert (Test-Path -LiteralPath $candidate)
}
Check 'Changed source hash prevents removal' {Must-Throw {Move-IncidentFile $candidate $profile $preserved ('0'*64)};Assert (Test-Path -LiteralPath $candidate)}
Check 'Extra NTFS streams prevent lossy automatic removal' {
    $extended='\\?\'+$candidate
    Set-Content -LiteralPath $extended -Stream 'NikkeTestMetadata' -Value 'INERT METADATA'
    try {Must-Throw {Move-IncidentFile $candidate $profile $preserved $verdict.SHA256};Assert (Test-Path -LiteralPath $candidate)} finally {Remove-Item -LiteralPath $extended -Stream 'NikkeTestMetadata'}
}
Check 'Out-of-profile removal is refused' {Must-Throw {Move-IncidentFile $candidate (Join-Path $fixture 'OtherProfile') $preserved $verdict.SHA256};Assert (Test-Path -LiteralPath $candidate)}
Check 'Reparse point cannot redirect file repair' {
    $link=Join-Path $profile 'junction';New-Item -ItemType Junction -Path $link -Target $preserved | Out-Null
    Must-Throw {Assert-NoReparse (Join-Path $link 'anything.bin')}
    Must-Throw {Get-TreeManifest $profile}
    # Remove only this verified junction itself, never recursively traverse its target.
    Assert (Test-PathWithin $link $fixture);[IO.Directory]::Delete($link)
}
Check 'Quarantine preserves byte-identical file and only removes selected source' {
    $result=Move-IncidentFile $candidate $profile $preserved $verdict.SHA256
    Assert (-not (Test-Path -LiteralPath $candidate));Assert (Test-Path -LiteralPath $fake);Assert ((Get-FileHash -LiteralPath $result.Preserved -Algorithm SHA256).Hash -ieq $verdict.SHA256)
}
Check 'Read-only tree manifest captures every remaining fixture file' {$manifest=@(Get-TreeManifest $profile);Assert ($manifest.Count -eq 2);Assert (@($manifest | Where-Object {-not $_.SHA256}).Count -eq 0)}
Check 'Every shipped PowerShell file parses without errors' {
    foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps*1')) {$tokens=$null;$parseErrors=$null;[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors) | Out-Null;Assert (@($parseErrors).Count -eq 0) $file.Name}
}
$failed=@($results | Where-Object {-not $_.Passed})
Save-Json (Join-Path $fixture 'test-results.json') @{PowerShell=$PSVersionTable.PSVersion.ToString();Passed=($results.Count-$failed.Count);Failed=$failed.Count;Tests=$results.ToArray();Fixture=$fixture;MalwareExecuted=$false;HostRegistryOrFirewallModified=$false}
Write-Host ('Test evidence: '+$fixture)
if ($failed.Count) {throw ($failed.Count.ToString()+' safety tests failed.')}

#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
    [ValidateSet('Audit','Plan','Apply','Verify')][string]$Mode='Audit',
    [string]$TargetProfile=$env:USERPROFILE,
    [string[]]$LauncherRoots=@(),
    [string]$OutputRoot='',
    [string]$ApprovedActionsPath='',
    [ValidatePattern('^[a-f0-9]{32}$')][string]$RunToken=([guid]::NewGuid().ToString('N'))
)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Lua.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.PostRecovery.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.FollowUp.psm1') -Force -DisableNameChecking
if (-not [Environment]::Is64BitProcess) {throw 'Use 64-bit Windows PowerShell or PowerShell 7.'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Mode -eq 'Apply' -and -not $admin) {throw 'Apply requires an elevated PowerShell. Audit/Plan do not modify the host.'}
$profilePath=Get-CanonicalPath $TargetProfile;Assert-NoReparse $profilePath
$profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop)
$matched=@($profiles | Where-Object {$_.LocalPath -ieq $profilePath -and -not $_.Special})
if ($matched.Count -ne 1) {throw 'The selected local profile must resolve to exactly one Windows user SID.'}
$targetSid=$matched[0].SID
if ($targetSid -notmatch '^S-1-5-21-[0-9-]+$') {throw 'Unsupported user SID; no mutation performed.'}
if (-not (Test-Path -LiteralPath ('Registry::HKEY_USERS\'+$targetSid))) {throw 'Selected user hive is not loaded. No hives are automatically mounted.'}
if (-not $OutputRoot) {$OutputRoot=Join-Path $env:LOCALAPPDATA 'NikkeRecovery\Evidence'}
$OutputRoot=Get-CanonicalPath $OutputRoot;Assert-NoReparse $OutputRoot
$runId=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+$RunToken
$runDir=Join-Path $OutputRoot $runId
if (Test-Path -LiteralPath $runDir) {throw 'Run directory collision.'}
New-ProtectedDirectory $runDir $targetSid
$backupDir=Join-Path $runDir 'preserved';New-Item -ItemType Directory -Path $backupDir -WhatIf:$false | Out-Null
$journal=Join-Path $runDir 'actions.jsonl'
$domains=@('insightjs.com','analytics.insightjs.com','insightjs.org');$ips=@('89.127.233.127','89.126.250.172')
$clsid='{E77CC89B-7401-4C04-8CED-149DB35ADD04}';$groups=@('NIKKE Recovery Kit','NIKKE Incident Containment 20261104')
$issues=New-Object 'Collections.Generic.List[object]';$actions=New-Object 'Collections.Generic.List[object]'
$stage='before';$index=0
function Add-Issue([string]$Area,[string]$Message) {$issues.Add([pscustomobject]@{Stage=$script:stage;Area=$Area;Message=$Message})}
function Write-Journal([string]$Action,[string]$Status,$Detail) {
    $record=[ordered]@{At=(Get-Date -Format o);Action=$Action;Status=$Status;Detail=$Detail}
    [IO.File]::AppendAllText($journal,((ConvertTo-Json $record -Compress -Depth 8)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
}
function Add-Action([string]$Kind,[string]$Target,[string]$Reason,$Extra=$null) {
    $script:index++;$actions.Add([pscustomobject]@{Id=$script:index;Kind=$Kind;Target=$Target;Reason=$Reason;Extra=$Extra})
}
# Installation discovery reads only vendor-named uninstall records and supplied roots.
$discovered=New-Object 'Collections.Generic.List[string]'
foreach ($p in @('C:\NIKKE\Launcher','C:\NIKKE_GOOGLE\launcher')+$LauncherRoots) {
    if ($p -and (Test-Path -LiteralPath $p)) {$discovered.Add((Get-CanonicalPath $p))}
}
foreach ($key in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',('Registry::HKEY_USERS\'+$targetSid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall'))) {
    if (-not (Test-Path -LiteralPath $key)) {continue}
    try {
        foreach ($sub in @(Get-ChildItem -LiteralPath $key)) {
            $item=Get-Item -LiteralPath $sub.PSPath
            if ([string]$item.GetValue('DisplayName') -match '(?i)NIKKE|GODDESS OF VICTORY|\uB2C8\uCF00') {
                $location=[string]$item.GetValue('InstallLocation')
                if ($location) {
                    $child=Join-Path $location 'Launcher'
                    if (Test-Path -LiteralPath $child) {$discovered.Add((Get-CanonicalPath $child))}
                    elseif (@(Get-KnownLauncherExecutables $location).Count) {$discovered.Add((Get-CanonicalPath $location))}
                }
            }
        }
    } catch {Add-Issue 'Installation discovery' $_.Exception.Message}
}
$launcherDirs=@($discovered | Sort-Object -Unique)
$launcherPrograms=New-Object 'Collections.Generic.List[string]'
foreach ($dir in $launcherDirs) {
    try {
        Assert-NoReparse $dir
        if ($dir.Length -lt 5 -or ([IO.DirectoryInfo]$dir).Parent -eq $null) {throw 'Refusing a drive root as launcher root.'}
        if ($dir -ieq $profilePath -or $dir -ieq $env:SystemRoot -or (Test-PathWithin $dir $env:SystemRoot) -or $dir -in @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData)) {throw 'Protected broad/system directory cannot be a launcher root.'}
        if (-not @(Get-KnownLauncherExecutables $dir).Count) {throw ('Unrecognized launcher directory; specify and review the installation: '+$dir)}
        $queue=New-Object 'Collections.Generic.Queue[string]';$queue.Enqueue($dir);$visited=0
        while ($queue.Count) {
            $next=$queue.Dequeue();$visited++;if ($visited -gt 5000) {throw 'Launcher discovery exceeded bounded directory limit.'}
            foreach ($item in @(Get-ChildItem -LiteralPath $next -Force)) {
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {Add-Issue 'Launcher discovery' ('Reparse point skipped: '+$item.FullName);continue}
                if ($item.PSIsContainer) {$queue.Enqueue($item.FullName)}
                elseif ($item.Extension -ieq '.exe') {$launcherPrograms.Add($item.FullName)}
            }
        }
    } catch {Add-Issue 'Launcher discovery' $_.Exception.Message}
}
$launcherPrograms=@($launcherPrograms | Sort-Object -Unique)
$cachePaths=@(foreach($area in @('Roaming','Local')){foreach($name in @('nikke_launcher','nikke_launcher_hmt','nikke_launcher_google')){Join-Path $profilePath ('AppData\'+$area+'\'+$name+'\tbs_cache')}})
$luaRoots=@($cachePaths)+@((Join-Path $profilePath 'AppData\Local\Temp'))+@($launcherDirs | Where-Object {@(Get-KnownLauncherExecutables $_).Count} | ForEach-Object {Join-Path $_ 'log'})
$hostsPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
function Get-State {
    $lua=Find-IncidentLuaFiles -Roots $luaRoots -ExcludeRoots @($OutputRoot)
    if($lua.Errors.Count -or $lua.Truncated -or $lua.FilesOverSizeLimit){Add-Issue 'Lua inspection coverage' ('Read errors: '+$lua.Errors.Count+'; truncated: '+$lua.Truncated+'; files over 16 MiB: '+$lua.FilesOverSizeLimit)}
    $dlls=New-Object 'Collections.Generic.List[object]';$keys=New-Object 'Collections.Generic.List[object]'
    $helper=Join-Path $profilePath 'AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper'
    if (Test-Path -LiteralPath $helper) {
        try {
            Assert-NoReparse $helper
            foreach ($dir in @(Get-ChildItem -LiteralPath $helper -Directory -Force)) {
                if ($dir.Name -notmatch '^[a-fA-F0-9]{64}$') {continue}
                Assert-NoReparse $dir.FullName
                foreach ($file in @(Get-ChildItem -LiteralPath $dir.FullName -File -Force | Where-Object {$_.Name -match '^platform_experience_helper\.dll(?:\.disabled.*)?$'})) {$dlls.Add((Get-IncidentDllVerdict $file.FullName $profilePath))}
            }
        } catch {Add-Issue 'DLL inspection' $_.Exception.Message}
    }
    foreach ($relative in @('Software\Classes\CLSID\','Software\Classes\WOW6432Node\CLSID\')) {
        $key='Registry::HKEY_USERS\'+$targetSid+'\'+$relative+$clsid
        try {
            $exists=Test-Path -LiteralPath $key;$value='';$unexpected=$false
            if ($exists) {
                $children=@(Get-ChildItem -LiteralPath $key)
                $unexpected=@($children | Where-Object {$_.PSChildName -ne 'InprocServer32'}).Count -gt 0
                if (Test-Path -LiteralPath ($key+'\InprocServer32')) {$value=[string](Get-Item -LiteralPath ($key+'\InprocServer32')).GetValue('')}
            }
            $keys.Add([pscustomobject]@{Path=$key;Exists=$exists;DefaultValue=$value;UnexpectedSubkeys=$unexpected;Disposition=(Get-RegistryDisposition $key $exists $value $dlls.ToArray() $unexpected)})
        } catch {Add-Issue 'Registry inspection' $_.Exception.Message}
    }
    $otherOverrides=New-Object 'Collections.Generic.List[object]'
    foreach ($p in @($profiles | Where-Object {$_.Loaded -and -not $_.Special -and $_.SID -ne $targetSid})) {
        foreach ($relative in @('Software\Classes\CLSID\','Software\Classes\WOW6432Node\CLSID\')) {
            $key='Registry::HKEY_USERS\'+$p.SID+'\'+$relative+$clsid
            try {if (Test-Path -LiteralPath $key) {$otherOverrides.Add([pscustomobject]@{SID=$p.SID;Path=$key;Disposition='Review other profile separately'})}} catch {Add-Issue 'Other user hive' $_.Exception.Message}
        }
    }
    $moduleHits=New-Object 'Collections.Generic.List[object]';$moduleErrors=0;$emptyModules=0;$processCount=0
    foreach ($process in @(Get-Process)) {
        $processCount++
        try {
            $modules=@($process.Modules);if (-not $modules.Count) {$emptyModules++}
            foreach ($module in $modules) {
                if ($module.ModuleName -ieq 'platform_experience_helper.dll') {$moduleHits.Add([pscustomobject]@{PID=$process.Id;Name=$process.ProcessName;Path=$module.FileName;PathMatchesIncident=($module.FileName -match '(?i)\\PlatformExperienceHelper\\[a-f0-9]{64}\\platform_experience_helper\.dll$')})}
            }
        } catch {$moduleErrors++}
    }
    $running=New-Object 'Collections.Generic.List[object]'
    try {
        $invalidProcessPaths=0
        foreach ($process in @(Get-CimInstance Win32_Process)) {
            if ($process.ExecutablePath) {
                try{$processPath=Get-CanonicalPath ([string]$process.ExecutablePath)}catch{$invalidProcessPaths++;continue}
                foreach ($root in $launcherDirs) {if (Test-PathWithin $processPath $root) {$running.Add([pscustomobject]@{PID=$process.ProcessId;Name=$process.Name;Path=$processPath});break}}
            }
        }
        if($invalidProcessPaths){Add-Issue 'Launcher processes' ('Unsupported process paths skipped: '+$invalidProcessPaths+'; remaining processes inspected.')}
    } catch {Add-Issue 'Launcher processes' $_.Exception.Message}
    $firewall=New-Object 'Collections.Generic.List[object]';$firewallProfiles=@()
    try {
        $found=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Group -in $groups})
        $addressById=@{};$appById=@{}
        if ($found.Count) {
            foreach ($filter in @($found | Get-NetFirewallAddressFilter -ErrorAction Stop)) {$addressById[$filter.InstanceID]=$filter}
            foreach ($filter in @($found | Get-NetFirewallApplicationFilter -ErrorAction Stop)) {$appById[$filter.InstanceID]=$filter}
        }
        foreach ($rule in $found) {
            if (-not $addressById.ContainsKey($rule.InstanceID) -or -not $appById.ContainsKey($rule.InstanceID)) {throw 'Incomplete firewall filter query.'}
            $address=$addressById[$rule.InstanceID];$app=$appById[$rule.InstanceID]
            $firewall.Add([pscustomobject]@{Name=$rule.Name;Enabled=([string]$rule.Enabled -eq 'True');Block=([string]$rule.Action -eq 'Block');Direction=[string]$rule.Direction;Profile=[string]$rule.Profile;Program=[string]$app.Program;RemoteAddress=@($address.RemoteAddress)})
        }
        $firewallProfiles=@(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled)
        if (@($firewallProfiles | Where-Object {-not $_.Enabled}).Count) {Add-Issue 'Firewall effectiveness' 'One or more Windows firewall profiles are disabled. A rule alone does not establish containment.'}
    } catch {Add-Issue 'Firewall query' $_.Exception.Message}
    $hosts='';try {$hosts=[IO.File]::ReadAllText($hostsPath)} catch {Add-Issue 'Hosts query' $_.Exception.Message}
    $defender=$null
    try {$defender=Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,FullScanStartTime,FullScanEndTime,RebootRequired;if (-not $defender.RealTimeProtectionEnabled) {Add-Issue 'Antivirus protection' 'Defender real-time protection is not active; another product may be responsible. No antivirus setting was changed.'}} catch {Add-Issue 'Defender query' $_.Exception.Message}
    $connections=@();try {$connections=@(Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.RemoteAddress -in $ips} | Select-Object OwningProcess,RemoteAddress,RemotePort,State)} catch {Add-Issue 'TCP query' $_.Exception.Message}
    return [pscustomobject]@{At=(Get-Date -Format o);DllCandidates=$dlls.ToArray();LuaInspection=$lua;Registry=$keys.ToArray();OtherUserOverrides=$otherOverrides.ToArray();MappedDlls=$moduleHits.ToArray();ProcessCoverage=@{Attempted=$processCount;ReadErrors=$moduleErrors;EmptyModuleLists=$emptyModules};LauncherProcesses=$running.ToArray();LauncherPrograms=$launcherPrograms;CachePaths=@($cachePaths | Where-Object {Test-Path -LiteralPath $_});Firewall=$firewall.ToArray();FirewallProfiles=$firewallProfiles;HostsBlocked=@($domains | Where-Object {Test-HostsBlocked $hosts $_});Defender=$defender;KnownC2Connections=$connections;NormalChromeHelperUntouched=$true}
}
Write-Host 'Inspecting incident indicators, loaded modules and containment...'
$before=Get-State;Save-Json (Join-Path $runDir 'before.json') $before
Write-Host 'Recording installed programs, startup relationships and referenced files (read-only)...'
$inventory=Get-PostRecoveryInventoryBounded -TargetSid $targetSid -TargetProfile $profilePath -OutputDirectory $runDir
Save-Json (Join-Path $runDir 'post-recovery-inventory.json') $inventory
Save-Json (Join-Path $runDir 'program-recovery-plan.json') (New-ProgramRecoveryPlan $inventory)
if($inventory.Errors.Count -or $inventory.Coverage.UnresolvedCommandsOrShortcuts -or $inventory.Coverage.MissingOrUnexaminedFiles){Add-Issue 'Post-recovery coverage' ('Errors: '+$inventory.Errors.Count+'; unresolved commands/shortcuts: '+$inventory.Coverage.UnresolvedCommandsOrShortcuts+'; missing/unexamined referenced files: '+$inventory.Coverage.MissingOrUnexaminedFiles)}
if($inventory.ConfirmedReferences.Count){Add-Issue 'Known incident reference' 'Known or strongly correlated incident content was found by the extended inventory. Preserve and review its specific location and relationships before repair.'}
foreach ($key in $before.Registry) {
    if ($key.Disposition -in @('MatchedIncidentOverride','EmptyIncidentOverride')) {Add-Action 'RemoveUserOverride' $key.Path $key.Disposition $key}
}
foreach ($dll in $before.DllCandidates) {
    if ($dll.Verdict -in @('Confirmed','StrongMatch')) {Add-Action 'QuarantineDll' $dll.Path $dll.Reason $dll}
}
foreach ($cache in $before.CachePaths) {Add-Action 'IsolateCache' $cache 'Isolate launcher web cache without deleting its contents'}
foreach ($direction in @('Outbound','Inbound')) {
    $covered=@($before.Firewall | Where-Object {$_.Enabled -and $_.Block -and $_.Direction -eq $direction -and $_.Profile -eq 'Any' -and $_.Program -eq 'Any' -and $ips[0] -in $_.RemoteAddress -and $ips[1] -in $_.RemoteAddress})
    if (-not $covered.Count) {Add-Action 'BlockC2' $direction 'Block both documented incident IP addresses'}
}
foreach ($program in $launcherPrograms) {
    foreach ($direction in @('Outbound','Inbound')) {
        $covered=@($before.Firewall | Where-Object {$_.Enabled -and $_.Block -and $_.Direction -eq $direction -and $_.Profile -eq 'Any' -and $_.Program -ieq $program -and 'Any' -in $_.RemoteAddress})
        if (-not $covered.Count) {Add-Action 'BlockLauncher' $program ('Block '+$direction+' launcher network access') $direction}
    }
}
if ($before.HostsBlocked.Count -ne $domains.Count) {Add-Action 'BlockDomains' $hostsPath 'Append missing incident-domain loopback blocks while preserving original bytes'}
Save-Json (Join-Path $runDir 'plan.json') $actions.ToArray()
$outcomes=New-Object 'Collections.Generic.List[object]'
if ($Mode -eq 'Apply') {
    $approved=$null
    if($ApprovedActionsPath){Assert-NoReparse $ApprovedActionsPath;$approved=@(Get-Content -LiteralPath $ApprovedActionsPath -Raw -Encoding UTF8|ConvertFrom-Json)}
    # Containment first, registry second, evidence-preserving file isolation last.
    $ordered=@($actions | Sort-Object @{Expression={switch ($_.Kind) {'BlockC2' {0};'BlockDomains' {1};'BlockLauncher' {2};'RemoveUserOverride' {3};'QuarantineDll' {4};default {5}}}},Id)
    foreach ($action in $ordered) {
        if($null -ne $approved){
            $match=@($approved|Where-Object {Test-ApprovedActionMatch $action $_})
            if(-not $match.Count){$outcomes.Add([pscustomobject]@{Id=$action.Id;Status='NotApplied';Detail='Not in the reviewed NikkeCR detection plan'});continue}
        }
        if (-not $PSCmdlet.ShouldProcess($action.Target,$action.Kind)) {$outcomes.Add([pscustomobject]@{Id=$action.Id;Status='NotApplied';Detail='WhatIf or declined'});continue}
        Write-Journal $action.Kind 'Started' $action
        try {
            $detail=$null
            switch ($action.Kind) {
                'BlockC2' {
                    $name='NIKKE-Recovery-C2-'+$action.Target
                    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {throw 'Existing tool-owned firewall rule differs; retained for manual review.'}
                    New-NetFirewallRule -Name $name -DisplayName $name -Group $groups[0] -Direction $action.Target -Action Block -RemoteAddress $ips -Profile Any -Enabled True | Out-Null
                }
                'BlockLauncher' {
                    Assert-NoReparse $action.Target
                    $hash=[Security.Cryptography.SHA256]::Create();try {$token=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($action.Target.ToLowerInvariant())))).Replace('-','').Substring(0,16)} finally {$hash.Dispose()}
                    $name='NIKKE-Recovery-App-'+$token+'-'+$action.Extra
                    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {throw 'Existing tool-owned application rule differs; retained for review.'}
                    New-NetFirewallRule -Name $name -DisplayName $name -Group $groups[0] -Direction $action.Extra -Action Block -Program $action.Target -Profile Any -Enabled True | Out-Null
                }
                'BlockDomains' {
                    Assert-NoReparse $hostsPath
                    $expected=(Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash
                    $backup=Join-Path $backupDir 'hosts.before.evidence';$null=Copy-VerifiedEvidence $hostsPath $backup $expected
                    $updated=Add-HostsBlockBytes ([IO.File]::ReadAllBytes($backup)) $domains
                    if ((Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash -ine $expected) {throw 'Hosts changed since backup; retained.'}
                    [IO.File]::WriteAllBytes($hostsPath,$updated);Clear-DnsClientCache
                }
                'RemoveUserOverride' {
                    $key=$action.Target
                    $nowValue='';if (Test-Path -LiteralPath ($key+'\InprocServer32')) {$nowValue=[string](Get-Item -LiteralPath ($key+'\InprocServer32')).GetValue('')}
                    if ($nowValue -cne $action.Extra.DefaultValue) {throw 'Registry target changed since plan; retained.'}
                    if (@(Get-ChildItem -LiteralPath $key | Where-Object {$_.PSChildName -ne 'InprocServer32'}).Count) {throw 'Unexpected registry child appeared; retained.'}
                    $allowed='Registry::HKEY_USERS\'+$targetSid+'\Software\Classes\'
                    if (-not $key.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -or -not $key.EndsWith('\'+$clsid,[StringComparison]::OrdinalIgnoreCase)) {throw 'Registry allowlist mismatch.'}
                    $backup=Join-Path $backupDir ('registry-'+$action.Id+'.reg.evidence')
                    & (Join-Path $env:SystemRoot 'System32\reg.exe') export $key.Substring('Registry::'.Length) $backup /y | Out-Null
                    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backup)) {throw 'Registry backup failed; no registry removal.'}
                    Remove-Item -LiteralPath $key -Recurse -Force
                    $detail=@{Preserved=$backup;SHA256=(Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash}
                }
                'QuarantineDll' {$detail=Move-IncidentFile $action.Target $profilePath $backupDir $action.Extra.SHA256}
                'IsolateCache' {
                    $source=Get-CanonicalPath $action.Target
                    if ($source -notin $cachePaths) {throw 'Cache path is not allowlisted.'}
                    $running=@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -and $_.ExecutablePath -in $launcherPrograms})
                    if ($running.Count) {throw 'Close launcher processes before cache isolation; cache retained.'}
                    $manifest=@(Get-TreeManifest $source);Save-Json (Join-Path $backupDir ('cache-'+$action.Id+'.manifest.json')) $manifest
                    $dest=Join-Path $backupDir ('cache-'+$action.Id+'.quarantined')
                    Assert-NoReparse $source;Assert-NoReparse $dest
                    if (-not (Test-PathWithin $source $profilePath) -or -not (Test-PathWithin $dest $backupDir) -or (Test-Path -LiteralPath $dest)) {throw 'Cache movement boundary check failed.'}
                    if ([IO.Path]::GetPathRoot($source) -ine [IO.Path]::GetPathRoot($dest)) {throw 'Cache isolation requires evidence on the same volume; source retained.'}
                    Move-Item -LiteralPath $source -Destination $dest
                    # Reset only this already-checked quarantined tree to inherit the protected evidence ACL.
                    & (Join-Path $env:SystemRoot 'System32\icacls.exe') $dest /reset /T /Q | Out-Null
                    if ($LASTEXITCODE -ne 0) {throw 'Quarantined cache ACL reset incomplete; inspect preserved tree.'}
                    $afterTree=@(Get-TreeManifest $dest)
                    $left=@($manifest | Sort-Object RelativePath | ForEach-Object {$_.RelativePath+'|'+$_.Length+'|'+$_.SHA256})
                    $right=@($afterTree | Sort-Object RelativePath | ForEach-Object {$_.RelativePath+'|'+$_.Length+'|'+$_.SHA256})
                    if (($left -join "`n") -cne ($right -join "`n")) {throw 'Cache post-move manifest differs; preserved at quarantine location for review.'}
                    $detail=@{Preserved=$dest;Files=$manifest.Count}
                }
            }
            Write-Journal $action.Kind 'Completed' $detail;$outcomes.Add([pscustomobject]@{Id=$action.Id;Status='Completed';Detail=$detail})
        } catch {Write-Journal $action.Kind 'Failed' $_.Exception.Message;$outcomes.Add([pscustomobject]@{Id=$action.Id;Status='Failed';Detail=$_.Exception.Message});Add-Issue 'Apply' $_.Exception.Message}
    }
}
$stage='after';$after=$before
if ($Mode -eq 'Apply' -and -not $WhatIfPreference) {Write-Host 'Rechecking host state after applied actions...';$after=Get-State}
Save-Json (Join-Path $runDir 'after.json') $after
$active=@($after.DllCandidates | Where-Object {$_.Verdict -in @('Confirmed','StrongMatch') -and $_.Path -match '(?i)\.dll$'}).Count+@($after.Registry | Where-Object {$_.Disposition -in @('MatchedIncidentOverride','EmptyIncidentOverride')}).Count
$review=@($after.DllCandidates | Where-Object Verdict -eq 'Review').Count+@($after.Registry | Where-Object Disposition -eq 'Review').Count+$after.OtherUserOverrides.Count+$after.LuaInspection.Findings.Count+$inventory.ConfirmedReferences.Count+@($inventory.BrowserHelpers | Where-Object Verdict -eq 'Review').Count
$verdict='NoKnownActiveIndicatorsWithinScope'
if ($active) {$verdict='KnownIndicatorsRemain'}
elseif ($after.MappedDlls.Count) {$verdict='AffectedApplicationExitRequired'}
elseif ($review -or $issues.Count -or $after.ProcessCoverage.ReadErrors -or $after.ProcessCoverage.EmptyModuleLists -or @($after.KnownC2Connections | Where-Object {$_.State -in @('Established','SynSent')}).Count) {$verdict='ReviewRequired'}
$summary=[ordered]@{Version='0.3.1-preview';At=(Get-Date -Format o);Mode=$Mode;WhatIf=[bool]$WhatIfPreference;TargetProfile=$profilePath;TargetSID=$targetSid;Administrator=$admin;Verdict=$verdict;WholeHostCleanClaim=$false;PlannedActions=$actions.Count;Outcomes=$outcomes.ToArray();RemainingKnownActiveIndicators=$active;MappedDllProcesses=$after.MappedDlls;ManualReviewItems=$review;Issues=$issues.ToArray();ProcessCoverage=$after.ProcessCoverage;ActiveCacheDirectories=$after.CachePaths;FirewallProfiles=$after.FirewallProfiles;EvidenceDirectory=$runDir;Limitations=@('Targeted incident remediation, not a guarantee against arbitrary commands or secondary malware.','Processes with inaccessible/empty module lists are unexamined; unloaded user hives and other user files are outside automatic repair.','No automatic reboot, offline scan, credential reset, external upload, sample execution, or modification of the HKLM COM registration, normal Chrome helper or Windows binaries.','Credentials and sessions already stolen remain exposed after local cleanup.','The historical malicious l.js and exact local Lua are unavailable; later l.js is a different build.','StrongMatch is a strict combined heuristic; rare false positives and changed variants remain possible.')}
$operationExitCode=Get-RecoveryExitCode $outcomes.ToArray() ([bool]$WhatIfPreference)
$summary.Version='0.3.1-preview'
$summary['LuaFindings']=$after.LuaInspection.Findings
$summary['PostRecoveryInventory']=Join-Path $runDir 'post-recovery-inventory.json'
$summary['PostRecoveryCoverage']=$inventory.Coverage
$summary.Limitations+=@('Lua hashes and structural leads are read-only findings. Outside a quarantined launcher cache, Lua files are retained for contextual review; their presence alone does not prove execution.','Post-recovery software inventory is a snapshot, not a trusted baseline; arbitrary program repair and removal of uncertain startup items are not automated.')
$summary['RunToken']=$RunToken;$summary['ExitCode']=$operationExitCode
Save-Json (Join-Path $runDir 'summary.json') $summary
$lines=@('NIKKE Recovery Kit 0.3.1-preview',('Mode: '+$Mode),('Result: '+$verdict),'Whole-host safety is NOT established.',('Known active indicators remaining: '+$active),('Mapped DLL processes: '+$after.MappedDlls.Count),('Manual-review findings: '+$review),('Planned actions: '+$actions.Count),('Evidence: '+$runDir),'','If a DLL remains mapped, save work, fully exit the affected application, then run Verify.','An antivirus scan with no detections is not proof that the intrusion had no further effects.','Account recovery must be performed separately from a trusted device.','','Actions:')+@($actions | ForEach-Object {$_.Id.ToString()+'. '+$_.Kind+' | '+$_.Target})+@('','Limitations:')+$summary.Limitations
[IO.File]::WriteAllLines((Join-Path $runDir 'REPORT.txt'),[string[]]$lines,(New-Object Text.UTF8Encoding($false)))
$hashes=@(Get-TreeManifest $runDir)
Save-Json (Join-Path $runDir 'EVIDENCE-SHA256.json') $hashes
Write-Host ('Result: '+$verdict);Write-Host ('Planned actions: '+$actions.Count);Write-Host ('Mapped DLL processes: '+$after.MappedDlls.Count);Write-Host ('Report: '+(Join-Path $runDir 'REPORT.txt'))
exit $operationExitCode

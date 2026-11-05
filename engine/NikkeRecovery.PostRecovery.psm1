# Read-only post-compromise inventory. Normal software is never declared malicious by name or lack of a signature.
Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
function Get-InventoryFileHash([string]$Path) {
    Assert-NoReparse $Path
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -gt 64MB){throw 'File exceeds inventory hashing limit'}
        $hash=[Security.Cryptography.SHA256]::Create()
        try{return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    }finally{$stream.Dispose()}
}
function Get-ProgramCommandPath([string]$Command,[string]$TargetProfile='') {
    if([string]::IsNullOrWhiteSpace($Command)){return $null}
    if($TargetProfile -and $TargetProfile -ine $env:USERPROFILE -and $Command -match '%(?:USERPROFILE|LOCALAPPDATA|APPDATA)%'){return $null}
    $s=[Environment]::ExpandEnvironmentVariables($Command.Trim())
    if($s -match '^"([^"\r\n]+\.(?:exe|dll|sys))"(?:\s|$)'){$s=$matches[1]}
    elseif($s -match '^([A-Za-z]:\\[^"\r\n]*?\.(?:exe|dll|sys))(?:\s|$)'){$s=$matches[1]}
    elseif($s -match '^\\SystemRoot\\'){$s=Join-Path ([Environment]::GetFolderPath('Windows')) $s.Substring(12);if($s -match '^(.*?\.(?:exe|dll|sys))(?:\s|$)'){$s=$matches[1]}}
    else{return $null}
    try{return Get-CanonicalPath $s}catch{return $null}
}
function Get-InventoryCoverage($Relationships,$Files) {
    $paths=@($Relationships | Where-Object FilePath | Select-Object -ExpandProperty FilePath -Unique)
    $done=@($Files | Select-Object -ExpandProperty Path -Unique)
    $pending=@($paths | Where-Object {$_ -notin $done}).Count
    $unexamined=@($Files | Where-Object Disposition -in @('Unexamined','Unreadable','Over64MiBLimit','ReferencedFileMissing')).Count
    return [pscustomobject]@{UnresolvedCommandsOrShortcuts=@($Relationships | Where-Object {-not $_.FilePath -or $_.Kind -eq 'StartupFile'}).Count;MissingOrUnexaminedFiles=($pending+$unexamined);ReferencedFileCount=$paths.Count;RecordedFileCount=$done.Count;PendingFileCount=$pending;HashedFileCount=@($Files | Where-Object SHA256).Count}
}
function Save-InventoryCheckpoint([string]$Path,$Value) {
    Assert-NoReparse $Path
    $next=$Path+'.next';Assert-NoReparse $next
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 20))
    $stream=[IO.File]::Open($next,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if([IO.File]::Exists($Path)){[IO.File]::Replace($next,$Path,[NullString]::Value)}else{[IO.File]::Move($next,$Path)}
}
function Get-PostRecoveryInventory([string]$TargetSid,[string]$TargetProfile,[int]$FileInspectionSeconds=120,[string]$PartialPath='') {
    if($TargetSid -notmatch '^S-1-5-21-[0-9-]+$'){throw 'Unsupported target SID'}
    $TargetProfile=Get-CanonicalPath $TargetProfile
    Write-Host 'Inventory: browser locations and installed programs...'
    $errors=New-Object 'Collections.Generic.List[object]';$programs=New-Object 'Collections.Generic.List[object]'
    $links=New-Object 'Collections.Generic.List[object]';$policies=New-Object 'Collections.Generic.List[object]'
    $artifacts=New-Object 'Collections.Generic.List[object]';$candidates=New-Object 'Collections.Generic.List[object]'
    $browserHelpers=New-Object 'Collections.Generic.List[object]'
    $wmi=@{}
    function Write-InventoryProgress {
        if(-not $PartialPath){return}
        $snapshot=[ordered]@{At=(Get-Date -Format o);ReadOnly=$true;TargetSid=$TargetSid;InstalledPrograms=$programs.ToArray();LaunchRelationships=$links.ToArray();ReferencedFiles=$artifacts.ToArray();BrowserPolicies=$policies.ToArray();BrowserHelpers=$browserHelpers.ToArray();BrowserRootsChecked=$browserRoots;WmiSubscriptions=$wmi;ConfirmedReferences=$candidates.ToArray();Errors=$errors.ToArray();Coverage=(Get-InventoryCoverage $links.ToArray() $artifacts.ToArray());FileInspectionCompleted=$false;Limitations=@('Partial inventory: enumeration or executable-content inspection did not complete. No clean-host claim.')}
        Save-InventoryCheckpoint $PartialPath $snapshot
    }
    $browserRoots=@('AppData\Local\Google\Chrome\User Data','AppData\Local\Microsoft\Edge\User Data','AppData\Local\BraveSoftware\Brave-Browser\User Data','AppData\Local\Vivaldi\User Data','AppData\Roaming\Opera Software\Opera Stable','AppData\Roaming\Opera Software\Opera GX Stable','AppData\Local\Chromium\User Data','AppData\Local\Naver\Naver Whale\User Data','AppData\Local\Yandex\YandexBrowser\User Data','AppData\Local\CocCoc\Browser\User Data','AppData\Local\Comodo\Dragon\User Data','AppData\Local\Thorium\User Data','AppData\Local\Epic Privacy Browser\User Data','AppData\Local\Google\Chrome\Application') | ForEach-Object {Join-Path $TargetProfile $_}
    $packages=Join-Path $TargetProfile 'AppData\Local\Packages'
    try{if(Test-Path -LiteralPath $packages){Assert-NoReparse $packages;foreach($p in @(Get-ChildItem -LiteralPath $packages -Directory -Filter 'TheBrowserCompany.Arc_*' -ErrorAction Stop)){$browserRoots+=Join-Path $p.FullName 'LocalCache\Local\Arc\User Data'}}}catch{$errors.Add([pscustomobject]@{Area='BrowserLocations';Error=$_.Exception.Message})}
    foreach($browserRoot in $browserRoots){
        $helper=Join-Path $browserRoot 'PlatformExperienceHelper'
        try {
            if(-not(Test-Path -LiteralPath $helper)){continue}
            Assert-NoReparse $helper
            $paths=@($helper)
            foreach($dir in @(Get-ChildItem -LiteralPath $helper -Directory -Force -ErrorAction Stop)){
                Assert-NoReparse $dir.FullName
                if($dir.Name -match '^[a-fA-F0-9]{64}$'){$paths+=$dir.FullName;$browserHelpers.Add([pscustomobject]@{Path=$dir.FullName;Kind='HashNamedFolder';Verdict='Review';Reason='Folder name alone is not an active-malware verdict';AutomaticRemoval=$false})}
            }
            foreach($p in $paths){foreach($f in @(Get-ChildItem -LiteralPath $p -File -Force -ErrorAction Stop | Where-Object {$_.Name -match '^platform_experience_helper\.dll(?:\..*)?$'})){
                $v=Get-IncidentDllVerdict $f.FullName $TargetProfile;$browserHelpers.Add($v)
                if($v.Verdict -in @('Confirmed','StrongMatch')){$candidates.Add([pscustomobject]@{Path=$f.FullName;Reason='Known or correlated incident DLL in browser helper location';AutomaticRemoval=$false})}
            }}
        }catch{$errors.Add([pscustomobject]@{Area='BrowserHelpers';Path=$helper;Error=$_.Exception.Message})}
    }
    $user='Registry::HKEY_USERS\'+$TargetSid
    foreach($base in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',($user+'\Software\Microsoft\Windows\CurrentVersion\Uninstall'))){
        try{
            if(-not(Test-Path -LiteralPath $base)){continue}
            foreach($k in @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)){
                $name=[string]$k.GetValue('DisplayName');if(-not $name){continue}
                $programs.Add([pscustomobject]@{Name=$name;Version=[string]$k.GetValue('DisplayVersion');Publisher=[string]$k.GetValue('Publisher');Location=[string]$k.GetValue('InstallLocation');RegistryPath=$k.Name;RepairCommandPresent=[bool]$k.GetValue('ModifyPath');AutomaticRepair=$false})
            }
        }catch{$errors.Add([pscustomobject]@{Area='InstalledPrograms';Path=$base;Error=$_.Exception.Message})}
    }
    Write-InventoryProgress
    foreach($hive in @($user,'Registry::HKEY_LOCAL_MACHINE')){
        foreach($relative in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')){
            $path=$hive+'\'+$relative
            try {
                if(Test-Path -LiteralPath $path) {
                    $k=Get-Item -LiteralPath $path -ErrorAction Stop
                    foreach($n in $k.GetValueNames()) {
                        $links.Add([pscustomobject]@{Kind='RegistryStartup';Source=$path;Name=$n;Command=[string]$k.GetValue($n);Arguments=$null;FilePath=(Get-ProgramCommandPath ([string]$k.GetValue($n)) $TargetProfile)})
                    }
                }
            } catch {$errors.Add([pscustomobject]@{Area='Startup';Path=$path;Error=$_.Exception.Message})}
        }
        foreach($relative in @('Software\Policies\Google\Chrome','Software\Policies\Microsoft\Edge','Software\Policies\BraveSoftware\Brave','Software\Policies\Naver\Whale')){
            $path=$hive+'\'+$relative
            try{if(Test-Path -LiteralPath $path){foreach($k in @((Get-Item -LiteralPath $path))+@(Get-ChildItem -LiteralPath $path -Recurse -ErrorAction Stop)){foreach($n in $k.GetValueNames()){$policies.Add([pscustomobject]@{Path=$k.Name;Name=$n;Value=$k.GetValue($n);Disposition='Policy inventory; may be legitimate organization policy'})}}}}catch{$errors.Add([pscustomobject]@{Area='BrowserPolicy';Path=$path;Error=$_.Exception.Message})}
        }
    }
    Write-InventoryProgress
    Write-Host 'Inventory: scheduled tasks and services...'
    try{foreach($t in @(Get-CimInstance -Namespace root/Microsoft/Windows/TaskScheduler -ClassName MSFT_ScheduledTask -OperationTimeoutSec 20 -ErrorAction Stop)){foreach($a in @($t.Actions)){if($a.CimClass.CimClassName -eq 'MSFT_TaskExecAction'){$links.Add([pscustomobject]@{Kind='ScheduledTask';Source=($t.TaskPath+$t.TaskName);Name=$t.TaskName;Command=[string]$a.Execute;Arguments=[string]$a.Arguments;FilePath=(Get-ProgramCommandPath ([string]$a.Execute))})}}}}catch{$errors.Add([pscustomobject]@{Area='ScheduledTasks';Error=$_.Exception.Message})}
    try{foreach($s in @(Get-CimInstance Win32_Service -OperationTimeoutSec 20 -ErrorAction Stop)){$links.Add([pscustomobject]@{Kind='Service';Source=$s.Name;Name=$s.DisplayName;Command=$s.PathName;Arguments=$null;FilePath=(Get-ProgramCommandPath $s.PathName);StartMode=$s.StartMode;State=$s.State})}}catch{$errors.Add([pscustomobject]@{Area='Services';Error=$_.Exception.Message})}
    # Registry fallback also exposes ServiceDll targets hidden behind a shared svchost.exe.
    # This records configured persistence, not proof that a service/driver is running.
    Write-Host 'Inventory: registered service, driver and ServiceDll targets...'
    $serviceRoot='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
    try {
        foreach($key in @(Get-ChildItem -LiteralPath $serviceRoot -ErrorAction Stop)) {
            try {
                $command=[string]$key.GetValue('ImagePath')
                if($command){$links.Add([pscustomobject]@{Kind='ServiceOrDriverRegistry';Source=$key.Name;Name=$key.PSChildName;Command=$command;Arguments=$null;FilePath=(Get-ProgramCommandPath $command $TargetProfile);StartMode=$key.GetValue('Start');State='Registry configuration only'})}
                $parameters=$key.PSPath+'\Parameters'
                if(Test-Path -LiteralPath $parameters){
                    $dll=[string](Get-Item -LiteralPath $parameters -ErrorAction Stop).GetValue('ServiceDll')
                    if($dll){$links.Add([pscustomobject]@{Kind='ServiceDllRegistry';Source=$parameters;Name=$key.PSChildName;Command=$dll;Arguments=$null;FilePath=(Get-ProgramCommandPath $dll $TargetProfile);State='Registry configuration only'})}
                }
            }catch{$errors.Add([pscustomobject]@{Area='ServiceRegistry';Path=$key.Name;Error=$_.Exception.Message})}
        }
    }catch{$errors.Add([pscustomobject]@{Area='ServiceRegistry';Path=$serviceRoot;Error=$_.Exception.Message})}
    Write-InventoryProgress
    foreach($class in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')){
        try{$wmi[$class]=@(Get-CimInstance -Namespace root/subscription -ClassName $class -OperationTimeoutSec 20 -ErrorAction Stop | Select-Object Name,Query,CommandLineTemplate,ExecutablePath,ScriptFileName,ScriptingEngine,Filter,Consumer)}catch{$errors.Add([pscustomobject]@{Area='WmiPersistence';Class=$class;Error=$_.Exception.Message})}
    }
    foreach($dir in @((Join-Path $TargetProfile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),(Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft\Windows\Start Menu\Programs\StartUp'))){
        try{if(Test-Path -LiteralPath $dir){Assert-NoReparse $dir;foreach($f in @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction Stop)){$links.Add([pscustomobject]@{Kind='StartupFile';Source=$dir;Name=$f.Name;Command=$null;Arguments=$null;FilePath=$f.FullName})}}}catch{$errors.Add([pscustomobject]@{Area='StartupFolder';Path=$dir;Error=$_.Exception.Message})}
    }
    Write-InventoryProgress
    Write-Host 'Inventory: bounded file hashing (signature verification is a separate check)...'
    $count=0;$clock=[Diagnostics.Stopwatch]::StartNew();$budgetExceeded=$false
    foreach($path in @($links | Where-Object FilePath | Select-Object -ExpandProperty FilePath -Unique)){
        $count++;if($count -gt 750 -or $clock.Elapsed.TotalSeconds -gt $FileInspectionSeconds){$budgetExceeded=$true;$errors.Add([pscustomobject]@{Area='ExecutableInspection';Error='File-count or elapsed-time budget reached; remaining references were not inspected'});break}
        $r=[ordered]@{Path=$path;Exists=$false;SHA256=$null;Signature='NotChecked';Signer=$null;Disposition='Unexamined'}
        try{
            Assert-NoReparse $path
            if(Test-Path -LiteralPath $path -PathType Leaf){$r.Exists=$true;$f=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if($f.Length -gt 64MB){$r.Disposition='Over64MiBLimit'}else{
                    $r.SHA256=Get-InventoryFileHash $path
                    if($r.SHA256 -in @('10e722777685e290e8fd5370d4c5cd1a40d0d7e91b93af0156faefe18467a3f1')){$r.Disposition='KnownIncidentHash';$candidates.Add([pscustomobject]@{Path=$path;Reason='Known incident SHA256 referenced by startup/service/task';AutomaticRemoval=$false})}
                    else{$r.Disposition='InventoryOnly'}
                    # Do not stall inventory on certificate-chain/network checks. Verify signatures separately for reviewed candidates.
                }
            }else{$r.Disposition='ReferencedFileMissing'}
        }catch{$r.Disposition='Unreadable';$errors.Add([pscustomobject]@{Area='ExecutableInspection';Path=$path;Error=$_.Exception.Message})}
        $artifacts.Add([pscustomobject]$r)
        if($PartialPath -and ($artifacts.Count % 10 -eq 0)){
            Write-InventoryProgress
        }
    }
    $unresolved=@($links | Where-Object {-not $_.FilePath -or $_.Kind -eq 'StartupFile'})
    return [pscustomobject]@{At=(Get-Date -Format o);ReadOnly=$true;TargetSid=$TargetSid;InstalledPrograms=$programs.ToArray();LaunchRelationships=$links.ToArray();ReferencedFiles=$artifacts.ToArray();BrowserPolicies=$policies.ToArray();BrowserHelpers=$browserHelpers.ToArray();BrowserRootsChecked=$browserRoots;WmiSubscriptions=$wmi;ConfirmedReferences=$candidates.ToArray();Errors=$errors.ToArray();Coverage=(Get-InventoryCoverage $links.ToArray() $artifacts.ToArray());FileInspectionCompleted=(-not $budgetExceeded);Limitations=@('Inventory is not an allowlist or clean-host verdict. Portable/MSIX apps, drivers, unloaded user hives and arbitrary scripts may be absent.','Browser helper inspection uses listed default locations and a bounded folder shape; non-default profiles and renamed DLLs may be missed.','Scheduled-task COM actions, shortcut destinations, script arguments and commands without resolved absolute executable paths need separate review.','No vendor repair, registry removal, task deletion, service stop, antivirus exclusion or credential access is performed.','Signature status does not establish that an application, its plugins or its runtime dependencies are safe.','This is a current snapshot; without a trusted baseline it cannot establish when or by whom a setting changed.')}
}
function Get-PostRecoveryInventoryBounded([string]$TargetSid,[string]$TargetProfile,[string]$OutputDirectory,[int]$TimeoutSeconds=180) {
    if($TargetSid -notmatch '^S-1-5-21-[0-9-]+$'){throw 'Unsupported target SID'}
    $TargetProfile=Get-CanonicalPath $TargetProfile;$OutputDirectory=Get-CanonicalPath $OutputDirectory
    Assert-NoReparse $OutputDirectory
    if(-not(Test-Path -LiteralPath $OutputDirectory -PathType Container)){throw 'Existing protected output directory required'}
    $result=Join-Path $OutputDirectory 'inventory-worker.json';$partial=Join-Path $OutputDirectory 'inventory-partial.json'
    if((Test-Path -LiteralPath $result) -or (Test-Path -LiteralPath $partial)){throw 'Inventory worker output collision'}
    $script=Join-Path $PSScriptRoot 'Collect-NikkeInventory.ps1'
    $ps=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $workerArguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$script+'"'),'-TargetSid',$TargetSid,'-TargetProfile',('"'+$TargetProfile+'"'),'-OutputDirectory',('"'+$OutputDirectory+'"'))
    $child=Start-Process -FilePath $ps -ArgumentList $workerArguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $OutputDirectory 'inventory-worker.stdout.txt') -RedirectStandardError (Join-Path $OutputDirectory 'inventory-worker.stderr.txt')
    $retainedHandle=$child.Handle
    $timer=[Diagnostics.Stopwatch]::StartNew();$timeout=$false
    while(-not $child.WaitForExit(1000)){if($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds){$timeout=$true;$child.Kill();$child.WaitForExit();break}}
    if(-not $timeout -and $child.ExitCode -eq 0 -and (Test-Path -LiteralPath $result)){$r=Get-Content -Encoding UTF8 -LiteralPath $result -Raw | ConvertFrom-Json}
    elseif(Test-Path -LiteralPath $partial){$r=Get-Content -Encoding UTF8 -LiteralPath $partial -Raw | ConvertFrom-Json}
    else{$r=[pscustomobject]@{At=(Get-Date -Format o);ReadOnly=$true;InstalledPrograms=@();LaunchRelationships=@();ReferencedFiles=@();BrowserPolicies=@();BrowserHelpers=@();ConfirmedReferences=@();Errors=@();Coverage=[pscustomobject]@{UnresolvedCommandsOrShortcuts=0;MissingOrUnexaminedFiles=0};Limitations=@('Inventory failed before a partial snapshot; no conclusions may be drawn.')}}
    if($timeout -or $null -eq $child.ExitCode -or $child.ExitCode -ne 0 -or -not(Test-Path -LiteralPath $result)){$r.Errors=@($r.Errors)+@([pscustomobject]@{Area='InventoryWorker';Error=('Read-only worker did not complete or produced no final inventory; timeout='+$timeout+'; exit='+$child.ExitCode)})}
    $r | Add-Member -NotePropertyName WorkerCompleted -NotePropertyValue (-not $timeout -and $child.ExitCode -eq 0 -and (Test-Path -LiteralPath $result)) -Force
    return $r
}
Export-ModuleMember -Function Get-InventoryFileHash,Get-ProgramCommandPath,Get-InventoryCoverage,Save-InventoryCheckpoint,Get-PostRecoveryInventory,Get-PostRecoveryInventoryBounded

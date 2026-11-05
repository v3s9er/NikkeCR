#requires -Version 5.1
[CmdletBinding()]param([string]$OutputRoot=$env:TEMP)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'scripts\NikkeCR.Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'scripts\NikkeCR.Exposure.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'scripts\NikkeCR.History.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'scripts\NikkeCR.Settings.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'engine\NikkeRecovery.Core.psm1') -Force -DisableNameChecking
$fixture=Join-Path $OutputRoot ('NikkeCRTests-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $fixture|Out-Null
$results=New-Object 'Collections.Generic.List[object]'
function Assert($condition,[string]$why='Assertion failed'){if(-not $condition){throw $why}}
function Check([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add(@{Name=$Name;Passed=$true});Write-Host ('PASS '+$Name)}catch{$results.Add(@{Name=$Name;Passed=$false;Error=$_.Exception.Message;Position=$_.InvocationInfo.PositionMessage});Write-Host ('FAIL '+$Name+' · '+$_.Exception.Message)}}
function MustThrow([scriptblock]$Body){$threw=$false;try{& $Body|Out-Null}catch{$threw=$true};Assert $threw 'Expected rejection'}
$har=Join-Path $fixture 'capture.har'
function Entry{return @{startedDateTime='2026-11-01T01:02:03Z';request=@{url=('https://analytics.insightjs.com/px/'+('a'*32));method='POST';postData=@{text='{"kind":"test-kind","value":"SENSITIVE_TEST_ONLY"}'}};response=@{status=200}}}
function Parse($entry){Save-Json $har @{log=@{entries=@($entry)}};return @(Read-CRHarTransfers $har)}
Check 'Known protocol + successful response gives bounded capture evidence' {$r=@(Parse (Entry));Assert ($r.Count -eq 1);Assert (-not $r[0].RemoteRetentionProven);Assert ($r[0].ValueSHA256 -eq (Get-CRHash 'SENSITIVE_TEST_ONLY'))}
foreach($case in @('GET','http','lookalike','wrong-path','bad-status','empty','extra-field','nonstring','bad-time')){$selected=$case;Check ('HAR rejects '+$case) {$e=Entry;switch($selected){'GET'{$e.request.method='GET'}'http'{$e.request.url=$e.request.url.Replace('https:','http:')}'lookalike'{$e.request.url=$e.request.url.Replace('insightjs.com','insightjs.com.example.org')}'wrong-path'{$e.request.url='https://analytics.insightjs.com/speed'}'bad-status'{$e.response.status=500}'empty'{$e.request.postData.text='{"kind":"x","value":""}'}'extra-field'{$e.request.postData.text='{"kind":"x","value":"x","extra":true}'}'nonstring'{$e.request.postData.text='{"kind":"x","value":123}'}'bad-time'{$e.startedDateTime='garbage'}};Assert (@(Parse $e).Count -eq 0)}}
Check 'Capture outputs omit unknown kind and raw value' {$e=Entry;$e.request.postData.text='{"kind":"SENSITIVE_KIND_TEST","value":"SENSITIVE_VALUE_TEST"}';$r=@(Parse $e)|ConvertTo-Json -Depth 6;Assert ($r -notmatch 'SENSITIVE_(KIND|VALUE)_TEST')}
Check 'Log redacts authorization and JSON credential values' {$s=Protect-CRText 'Authorization: Bearer ABCSECRET token=XYZSECRET {"password":"JSON SECRET"} ghp_1234567890abcdefghijkl';Assert ($s -notmatch 'ABCSECRET|XYZSECRET|JSON SECRET|1234567890abcdefghijkl')}
Check 'Similar domain does not match indicator' {Assert (-not(Test-CRIndicator 'https://insightjs.com.example.org/file'));Assert (Test-CRIndicator 'https://analytics.insightjs.com/file')}
Check 'Large artifacts are explicitly rejected' {$p=Join-Path $fixture 'large.txt';[IO.File]::WriteAllText($p,('A'*100));MustThrow {Read-CRText $p 10}}
Check 'Scanner marks bounded traversal incomplete' {$p=Join-Path $fixture 'bounded';New-Item -ItemType Directory -Path $p|Out-Null;1..10|ForEach-Object {[IO.File]::WriteAllText((Join-Path $p ($_.ToString()+'.txt')),'inert')};$r=Find-CRFiles @($p) @('*.txt') 2 1 10;Assert $r.Truncated}
$profile=Join-Path $fixture 'Profile';$aws=Join-Path $profile '.aws';New-Item -ItemType Directory -Path $aws -Force|Out-Null;$credential=Join-Path $aws 'credentials';[IO.File]::WriteAllText($credential,'SECRET_MUST_NOT_BE_READ')
Check 'Target presence is potential exposure, never exfiltration' {$r=@(Get-CRExposureCatalog $profile $true);Assert (@($r|Where-Object {$_.Title -eq 'AWS' -and $_.Status -eq 'PotentialExposure'}).Count -eq 1);Assert (@($r|Where-Object Status -eq 'ConfirmedExfiltration').Count -eq 0);Assert (($r|ConvertTo-Json -Depth 8) -notmatch 'SECRET_MUST_NOT_BE_READ');Assert ($r.Count -ge 135)}
Check 'Locked credential file content is not opened' {$s=[IO.File]::Open($credential,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);try{$r=@(Get-CRExposureCatalog $profile $true);Assert (@($r|Where-Object {$_.Title -eq 'AWS' -and $_.Status -eq 'PotentialExposure'}).Count -eq 1)}finally{$s.Dispose()}}
Check 'Unattributed HAR never confirms theft from the scanned host' {
    $t=@(Parse (Entry));$r=@(Get-CRExposureCatalog $profile $true $t)
    Assert (@($r|Where-Object Status -eq 'CapturedTransfer').Count -eq 1)
    Assert (@($r|Where-Object Status -eq 'ConfirmedExfiltration').Count -eq 0)
}
Check 'Staging filename alone is not exfiltration' {$r=@(Get-CRExposureCatalog $profile $true @() @([pscustomobject]@{Kind='k2f-keyscan-test.db';Path='synthetic';At=''}));Assert (@($r|Where-Object Status -eq 'CollectionTrace').Count -eq 1);Assert (@($r|Where-Object Status -eq 'ConfirmedExfiltration').Count -eq 0)}
Check 'Completed exact DLL quarantine becomes a repaired finding' {
    $path=Join-Path $fixture 'reported-dll.quarantined-fixture';$preserved=Join-Path $fixture 'preserved-synthetic.bin';[IO.File]::WriteAllText($preserved,'synthetic DLL content');$hash=(Get-FileHash $preserved).Hash
    $reference=[pscustomobject]@{Path=$path;Reason='Synthetic incident reference'}
    $plan=@([pscustomobject]@{Id=2;Kind='QuarantineDll';Target=$path;Extra=[pscustomobject]@{SHA256=$hash}})
    $outcomes=@([pscustomobject]@{Id=2;Status='Completed';Detail=[pscustomobject]@{SHA256=$hash;Preserved=$preserved;OriginalStillExists=$false}})
    Assert ((Get-CRInventoryReferenceFinding $reference 'Repair' $plan $outcomes).Status -eq 'Repaired')
    [IO.File]::WriteAllText($path,'synthetic');try{Assert ((Get-CRInventoryReferenceFinding $reference 'Repair' $plan $outcomes).Status -eq 'Review')}finally{Remove-Item -LiteralPath $path -Force}
    $outcomes[0].Detail.SHA256='0'*64;Assert ((Get-CRInventoryReferenceFinding $reference 'Repair' $plan $outcomes).Status -eq 'Review')
    Assert ((Get-CRInventoryReferenceFinding $reference 'Detect' $plan @()).Status -eq 'Review')
}
Check 'Launcher log distinguishes registered, failed and started runs' {
    $log="`"startup failed: unrelated`"`n`"k2f_chan registered`"`n`"startup failed: EIO`"`n`"k2f_chan registered`"`n`"agent started as SYNTHETIC_HOST_043`""
    $r=Get-CRLauncherLogSignals $log 'synthetic-debug.log'
    Assert $r.AgentLoaded;Assert $r.AgentStarted;Assert $r.StartupFailed
    Assert (@($r.Findings|Where-Object Title -eq '악성 에이전트 채널 등록 기록').Count -eq 2)
    Assert (@($r.Findings|Where-Object Title -eq '악성 에이전트 시작 실패 기록').Count -eq 1)
    Assert (@($r.Findings|Where-Object Title -eq '악성 에이전트 시작 기록').Count -eq 1)
    $f=Get-CRLauncherLogSignals "`"k2f_chan registered`"`n`"startup failed: EIO`"" 'synthetic-debug.log'
    Assert $f.AgentLoaded;Assert $f.StartupFailed;Assert (-not $f.AgentStarted)
    Assert (@($f.Findings|Where-Object Title -eq '악성 에이전트 시작 기록').Count -eq 0)
    $u=Get-CRLauncherLogSignals "`"k2f_chan registered`"`nthe user adopted a cat`n`"startup failed: EIO`"" 'synthetic-debug.log'
    Assert (-not $u.AgentStarted);Assert $u.StartupFailed
}
Check 'Sparse event XML omits command lines' {$e=[pscustomobject]@{TimeCreated=[datetime]'2026-11-01';RecordId=1;LogName='Synthetic';Id=1};$e|Add-Member ScriptMethod ToXml {'<Event><EventData><Data Name="Image">C:\Example\tool.exe</Data><Data Name="CommandLine">token=SHOULD_NOT_SURVIVE</Data><Data Name="ProcessGuid">{synthetic}</Data></EventData></Event>'};$r=Convert-CRWindowsEvent $e;Assert ($r.ProcessGuid -eq '{synthetic}');Assert (($r|ConvertTo-Json) -notmatch 'SHOULD_NOT_SURVIVE')}
Check 'Namespaced events with empty fields preserve provider and image' {
    $e=[pscustomobject]@{TimeCreated=[datetime]'2026-11-01';RecordId=2;LogName='System';Id=7045}
    $e|Add-Member ScriptMethod ToXml {'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/></System><EventData><Data Name="Empty"/><Data Name="ImagePath">C:\Example\service.exe</Data></EventData></Event>'}
    $r=Convert-CRWindowsEvent $e;Assert ($r.Provider -ceq 'Service Control Manager');Assert ($r.Image -ceq 'C:\Example\service.exe')
}
Check 'Service command arguments do not enter history or visible findings' {
    $e=[pscustomobject]@{TimeCreated=[datetime]'2026-11-01';RecordId=3;LogName='System';Id=7045}
    $e|Add-Member ScriptMethod ToXml {'<Event><EventData><Data Name="ImagePath">"C:\Example\service.exe" --password=SECRET_ARGUMENT</Data></EventData></Event>'}
    $r=Convert-CRWindowsEvent $e;Assert ($r.Image -ceq 'C:\Example\service.exe');Assert (($r|ConvertTo-Json) -notmatch 'SECRET_ARGUMENT')
}
Check 'Depth-bounded scans report skipped subdirectories' {
    $dir=Join-Path $fixture 'depth\child';New-Item -ItemType Directory -Path $dir -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $dir 'inert.txt'),'fixture');$r=Find-CRFiles @((Split-Path $dir -Parent)) @('*.txt') 100 0 10
    Assert $r.Truncated;Assert ($r.Files.Count -eq 0)
}
Check 'Package and entry point parse checks' {Assert-CRPackage $root;foreach($f in Get-ChildItem -LiteralPath $root -Recurse -File|Where-Object {$_.Extension -in @('.ps1','.psm1')}){$errors=$null;$tokens=$null;$null=[Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$errors);Assert ($errors.Count -eq 0) ($f.Name+': '+($errors -join '; '))}}
Check 'GUI package check refuses a linked ancestor' {
    $assembly=[Reflection.Assembly]::LoadFrom((Join-Path $root 'NikkeCR.exe'))
    $type=$assembly.GetType('NikkeCR.MainForm',$true)
    $method=$type.GetMethod('AssertNoReparse',[Reflection.BindingFlags]'NonPublic,Static')
    Assert ($null -ne $method)
    $normal=Join-Path $fixture 'normal';New-Item -ItemType Directory -Path $normal|Out-Null
    $normalPath=[string](Join-Path $normal 'missing.txt');$null=$method.Invoke($null,([object[]]@($normalPath)))
    $link=Join-Path $fixture 'package-link';New-Item -ItemType Junction -Path $link -Target $normal|Out-Null
    try{$linkedPath=[string](Join-Path $link 'missing.txt');MustThrow {$method.Invoke($null,([object[]]@($linkedPath)))}}finally{Assert (Test-PathWithin $link $fixture);[IO.Directory]::Delete($link)}
}
Check 'Changed approved setting is refused without mutation' {
    $module=Get-Module NikkeCR.Settings
    $expected=[pscustomobject]@{Id='test';Path='HKCU:\Software\NeverMutate';Name='x';ValueHash='old'}
    $r=& $module {param($e,$b)function Get-CRSettings{return [pscustomobject]@{Plans=@([pscustomobject]@{Id='test';Path='HKCU:\Software\NeverMutate';Name='x';ValueHash='changed'})}};Repair-CRSettings 'S-1-5-21-1-2-3-1001' 'C:\Users\Synthetic' $b @($e)} $expected $fixture
    Assert ($r.Status -eq 'Failed')
}
Check 'Unicode JSON stays intact with the PowerShell 5.1 reader' {
    $p=Join-Path $fixture 'unicode.json';Save-Json $p @{Name='한글 프로그램';Path='C:\검증\파일.exe'}
    $r=Get-Content -Encoding UTF8 -LiteralPath $p -Raw|ConvertFrom-Json;Assert ($r.Name -ceq '한글 프로그램');Assert ($r.Path -ceq 'C:\검증\파일.exe')
}
Check 'Settings repair preserves value bytes and removes only a literal selected name' {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$id=[guid]::NewGuid().ToString('N');$key='Registry::HKEY_USERS\'+$sid+'\Software\NikkeCRTest-'+$id
    New-Item -Path $key -Force|Out-Null;New-ItemProperty -LiteralPath $key -Name 'Value[*]' -Value '한글 inert backup' -PropertyType String|Out-Null;New-ItemProperty -LiteralPath $key -Name 'Value1' -Value 'KEEP' -PropertyType String|Out-Null
    $p=[pscustomobject]@{Id=$id;Path=$key;Name='Value[*]';Value='한글 inert backup';Kind='String';ValueHash=(Get-CRHash ('String|'+('한글 inert backup'|ConvertTo-Json -Compress)));Reason='Synthetic test only'}
    try{
        $module=Get-Module NikkeCR.Settings
        $out=& $module {param($plan,$sid,$folder)
            $old=(Get-Item Function:Get-CRSettings).ScriptBlock
            try{$script:fixturePlan=$plan;Set-Item Function:script:Get-CRSettings {return [pscustomobject]@{Plans=@($script:fixturePlan)}};$r=@(Repair-CRSettings $sid 'C:\Users\Synthetic' $folder @($plan));return $r}
            finally{Set-Item Function:script:Get-CRSettings $old;Remove-Variable fixturePlan -Scope Script -ErrorAction SilentlyContinue}
        } $p $sid $fixture
        Assert ($out.Status -eq 'Repaired');Assert ('Value[*]' -notin (Get-Item -LiteralPath $key).GetValueNames());Assert ((Get-Item -LiteralPath $key).GetValue('Value1') -ceq 'KEEP')
        $backup=Read-CRText (Join-Path $fixture ($id+'.registry-value.json'))|ConvertFrom-Json;Assert ($backup.Value -ceq '한글 inert backup')
    }finally{Remove-Item -LiteralPath $key -Force}
}
Save-Json (Join-Path $fixture 'test-results.json') @{PowerShell=$PSVersionTable.PSVersion.ToString();Passed=@($results|Where-Object Passed).Count;Failed=@($results|Where-Object {-not $_.Passed}).Count;Tests=$results.ToArray();Fixture=$fixture}
Write-Host ('Results: '+$fixture)
if(@($results|Where-Object {-not $_.Passed}).Count){exit 1};exit 0

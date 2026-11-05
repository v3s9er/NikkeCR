Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.Common.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot '..\engine\NikkeRecovery.Core.psm1') -DisableNameChecking
function Test-CRIndicator([string]$Text){return $Text -match '(?i)(?<![a-z0-9_.-])(?:analytics\.)?insightjs\.(?:com|org)(?![a-z0-9_.-])|(?<![0-9.])89\.(?:127\.233\.127|126\.250\.172)(?![0-9.])|platform_experience_helper\.dll|k2f_chan|k2f\.agent\.state'}
function Convert-CRWindowsEvent($Event){
    $xmlText=$Event.ToXml();if($xmlText.Length -gt 1MB){throw 'Event XML exceeds the parser limit'}
    $x=New-Object Xml.XmlDocument;$x.XmlResolver=$null;$x.LoadXml($xmlText);$d=@{}
    foreach($a in $x.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]')){$d[$a.GetAttribute('Name')]=[string]$a.InnerText}
    $providerNode=$x.SelectSingleNode('/*[local-name()="Event"]/*[local-name()="System"]/*[local-name()="Provider"]');$provider=if($providerNode){$providerNode.GetAttribute('Name')}else{''}
    $image='';foreach($key in @('Image','NewProcessName','Application','ImagePath','ServiceFileName')){if($d.ContainsKey($key)){
        $value=[string]$d[$key]
        if($key -in @('ImagePath','ServiceFileName')){
            if($value -match '^"([^"]+)"'){$image=$matches[1]}elseif($value -match '^(.*?\.(?:exe|sys|dll))(?=\s|$)'){$image=$matches[1]}
        }else{$image=$value};break
    }}
    $match=Test-CRIndicator ($d.Values -join ' ')
    $launcher=($image -match '(?i)\\nikke_launcher(?:_google)?\.exe$')
    return [pscustomobject]@{At=$Event.TimeCreated.ToUniversalTime().ToString('o');RecordId=$Event.RecordId;Log=$Event.LogName;Provider=$provider;EventId=$Event.Id;Image=$image;ParentImage=$d['ParentImage'];ProcessGuid=$d['ProcessGuid'];ParentProcessGuid=$d['ParentProcessGuid'];DestinationIp=$d['DestinationIp'];DestinationHostname=$d['DestinationHostname'];DestinationPort=$d['DestinationPort'];QueryName=$d['QueryName'];TargetFilename=$d['TargetFilename'];Indicator=$match;Launcher=$launcher;CommandLineOmitted=$true}
}
function Get-CRLauncherLogSignals([string]$Body,[string]$Source){
    $findings=New-Object 'Collections.Generic.List[object]';$loaded=$false;$started=$false;$failed=$false;$open=$false;$lineNumber=0
    foreach($line in ($Body -split "`n")){
        $lineNumber++
        if($line -match '(?i)k2f_chan\s+registered'){
            $loaded=$true;$open=$true
            $findings.Add((New-CRFinding '과거 실행·통신' 'Review' '악성 에이전트 채널 등록 기록' '런처 로그에서 채널 등록을 확인했습니다. 이 한 줄만으로 서버 연결, 명령 실행 또는 유출을 확정하지 않습니다.' ($Source+':'+$lineNumber)))
        }elseif($line -match '(?i)"(?:agent started as |adopted |resuming )'){
            $loaded=$true;$started=$true;$open=$false
            $findings.Add((New-CRFinding '과거 실행·통신' 'Review' '악성 에이전트 시작 기록' '런처 로그에서 에이전트의 후속 시작 단계를 확인했습니다. 공격자 명령과 실제 유출 내용은 별도로 확인해야 합니다.' ($Source+':'+$lineNumber)))
        }elseif($open -and $line -match '(?i)"startup failed'){
            $failed=$true;$open=$false
            $findings.Add((New-CRFinding '과거 실행·통신' 'Review' '악성 에이전트 시작 실패 기록' '채널 등록 뒤 시작 실패가 기록됐습니다. 이 실행의 후속 명령 성공은 확인되지 않으며 다른 실행이 성공했을 가능성은 별도로 조사해야 합니다.' ($Source+':'+$lineNumber)))
        }
    }
    return [pscustomobject]@{Findings=$findings.ToArray();AgentLoaded=$loaded;AgentStarted=$started;StartupFailed=$failed}
}
function Get-CRHistory([string]$Profile,[string[]]$LauncherRoots,[string]$EvidenceRoot='', [datetime]$Since=[datetime]'2026-09-27', [int]$MaxEvents=3000){
    $findings=New-Object 'Collections.Generic.List[object]';$coverage=New-Object 'Collections.Generic.List[object]';$events=New-Object 'Collections.Generic.List[object]';$staging=New-Object 'Collections.Generic.List[object]';$agent=$false;$agentStarted=$false;$startupFailed=$false
    $specs=@(
        @('Microsoft-Windows-Sysmon/Operational',@(1,3,11,13,22)),
        @('Security',@(4688,5156,4698)),
        @('System',@(7045)),
        @('Microsoft-Windows-TaskScheduler/Operational',@(106,140)),
        @('Application',@(1033,11707)),
        @('Microsoft-Windows-DNS-Client/Operational',@(3008))
    )
    foreach($spec in $specs){$name=$spec[0];try{
        $info=Get-WinEvent -ListLog $name -ErrorAction Stop
        if(-not $info.IsEnabled){throw 'Log disabled'}
        $records=@();try{$records=@(Get-WinEvent -FilterHashtable @{LogName=$name;Id=$spec[1];StartTime=$Since} -MaxEvents ($MaxEvents+1) -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){throw}}
        $cut=$records.Count -gt $MaxEvents;$kept=0;$parseErrors=0
        foreach($e in @($records|Select-Object -First $MaxEvents)){try{$row=Convert-CRWindowsEvent $e;$events.Add($row);$kept++}catch{$parseErrors++}}
        $coverage.Add([pscustomobject]@{Source=$name;Status=$(if($cut){'Truncated'}elseif($parseErrors){'Partial'}else{'Read'});Read=$kept;ParseErrors=$parseErrors;Since=$Since.ToString('o');RetentionComplete=$false;Detail=('최근 이벤트부터 조회. 해석 실패 '+$parseErrors+'개. 로그 보존 기간 전체 또는 사건 기간의 완전성을 보장하지 않음.')})
    }catch{$coverage.Add([pscustomobject]@{Source=$name;Status='Unavailable';Read=0;Since=$Since.ToString('o');RetentionComplete=$false;Detail=(Protect-CRText $_.Exception.Message)})}}
    $guids=@{};foreach($e in $events){if(($e.Indicator -or $e.Launcher) -and $e.ProcessGuid){$guids[$e.ProcessGuid]=$true}}
    foreach($e in $events){
        $linked=($e.ParentProcessGuid -and $guids.ContainsKey($e.ParentProcessGuid))
        if($e.Indicator -or $e.Launcher -or $linked){
            $why='이벤트의 경로·도메인·IP 또는 ProcessGuid 관계가 사건 지표와 연결됨. 연결 기록은 전송 내용의 증거가 아님.'
            if($linked){$why='ProcessGuid로 연결된 자식 프로세스. 추가 실행 후보이며 악성 여부는 별도 확인 필요.'}
            $findings.Add((New-CRFinding '과거 실행·통신' 'Review' ($e.Log+' / '+$e.EventId+' / '+$e.Image) $why ($e.Log+'#'+$e.RecordId) $e.At))
        }elseif($e.EventId -eq 7045 -and $e.Provider -eq 'Service Control Manager'){$findings.Add((New-CRFinding '설치·서비스 이력' 'Review' ('서비스 설치: '+$e.Image) '사건 조사 기간 내 서비스 설치 기록. 설치 시점만으로 악성으로 판정하지 않음.' ($e.Log+'#'+$e.RecordId) $e.At))}
    }
    # Only original launcher logs are interpreted. Generated analysis reports are not proof of execution.
    $roots=@($LauncherRoots|ForEach-Object {Join-Path $_ 'intl_service'})
    if($EvidenceRoot){Assert-NoReparse $EvidenceRoot;$roots+=@($EvidenceRoot)}
    $logs=Find-CRFiles -Roots $roots -Names @('debug.log','debug.log.evidence') -MaxFiles 10000 -MaxDepth 8 -Seconds 20
    foreach($path in $logs.Files){try{
        $body=Read-CRText $path 32MB;$signals=Get-CRLauncherLogSignals $body $path
        foreach($finding in $signals.Findings){$findings.Add($finding)}
        if($signals.AgentLoaded){$agent=$true};if($signals.AgentStarted){$agentStarted=$true};if($signals.StartupFailed){$startupFailed=$true}
    }catch{$coverage.Add([pscustomobject]@{Source=$path;Status='Unavailable';Detail='로그를 읽지 못함'})}}
    $coverage.Add([pscustomobject]@{Source='Launcher debug.log';Status=$(if($logs.Truncated -or $logs.Errors.Count){'Partial'}else{'Read'});Read=$logs.Files.Count;Detail='지정된 설치 경로와 선택한 증거 폴더에서만 원본 로그 이름을 찾음.'})
    $temps=Find-CRFiles -Roots @((Join-Path $Profile 'AppData\Local\Temp')) -Names @('k2f-bcreds-*','k2f-keyscan-*','k2f_screen_*') -MaxFiles 6000 -MaxDepth 3 -Seconds 10
    foreach($path in $temps.Files){$f=Get-Item -LiteralPath $path;$staging.Add([pscustomobject]@{Kind=$f.Name;Path=$path;At=$f.LastWriteTimeUtc.ToString('o')})}
    $coverage.Add([pscustomobject]@{Source='Temporary collection filenames';Status=$(if($temps.Truncated -or $temps.Errors.Count){'Partial'}else{'Read'});Read=$temps.Files.Count;Detail='파일 이름·시간만 확인. 내용 또는 전송 여부는 확인하지 않음.'})
    foreach($c in $coverage|Where-Object {$_.Status -in @('Unavailable','Partial','Truncated')}){$findings.Add((New-CRFinding '검사 범위' 'CoverageGap' ([string]$c.Source) ([string]$c.Detail)))}
    $findings.Add((New-CRFinding '검사 범위' 'CoverageGap' 'SRUM·USN·삭제 파일·암호화 트래픽' '이 버전은 SRUDB.dat/USN을 직접 파싱하거나 삭제 파일을 복구하지 않음. SRUM 전송량만으로 유출 파일을 특정할 수 없음.'))
    return [pscustomobject]@{Findings=$findings.ToArray();Coverage=$coverage.ToArray();Events=$events.ToArray();AgentEvidence=$agent;AgentStartedTrace=$agentStarted;AgentStartupFailedTrace=$startupFailed;Staging=$staging.ToArray();ExfiltrationProven=$false}
}
Export-ModuleMember -Function Test-CRIndicator,Convert-CRWindowsEvent,Get-CRLauncherLogSignals,Get-CRHistory

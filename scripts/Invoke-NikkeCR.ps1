#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Detect','Repair')][string]$Mode='Detect',[string]$TargetProfile=$env:USERPROFILE,[Parameter(Mandatory=$true)][string]$JobRoot,[string]$EvidenceRoot='', [string]$HarPath='', [string]$PreviousReport='', [string]$PreviousSHA256='')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
# A GUI started by PowerShell 7 can inherit its module path. Windows PowerShell
# must resolve its own inbox security/CIM modules, not incompatible PS7 binaries.
if($PSVersionTable.PSVersion.Major -eq 5){$env:PSModulePath=Join-Path $PSHOME 'Modules'}
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.Common.psm1') -DisableNameChecking
Import-Module (Join-Path $root 'engine\NikkeRecovery.Core.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.Exposure.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.History.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.Settings.psm1') -DisableNameChecking
$TargetProfile=Get-CanonicalPath $TargetProfile;$JobRoot=Get-CanonicalPath $JobRoot
Assert-NoReparse $TargetProfile;Assert-NoReparse $JobRoot
$allowed=Join-Path $TargetProfile 'NikkeCR-Evidence\Runs'
if(-not(Test-PathWithin $JobRoot $allowed) -or ([IO.DirectoryInfo]$JobRoot).Parent.FullName -ine $allowed){throw 'Job folder must be directly under the selected profile NikkeCR-Evidence Runs directory'}
$profiles=@(Get-CimInstance Win32_UserProfile|Where-Object {$_.LocalPath -ieq $TargetProfile -and -not $_.Special})
if($profiles.Count -ne 1){throw 'Profile SID lookup failed'};$sid=$profiles[0].SID
if($sid -notmatch '^S-1-5-21-[0-9-]+$'){throw 'Unsupported SID'}
New-ProtectedDirectory $JobRoot $sid
$log=Join-Path $JobRoot 'progress.log';$reportPath=Join-Path $JobRoot 'result.json';$statusPath=Join-Path $JobRoot 'status.json'
function Stage([string]$Name,[int]$Percent){Write-CRLog $log $Name;Save-Json $statusPath @{Stage=$Name;Percent=$Percent;Finished=$false}}
function ReadJson([string]$Path){return (Read-CRText $Path|ConvertFrom-Json)}
try{
    Stage '배포 파일 무결성과 대상 사용자 확인' 2;Assert-CRPackage $root
    $admin=(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($Mode -eq 'Repair' -and -not $admin){throw '복구는 Windows 관리자 승인이 필요합니다.'}
    $prior=$null;$approval=''
    if($Mode -eq 'Repair'){
        if($PreviousSHA256 -notmatch '^[a-fA-F0-9]{64}$' -or -not(Test-PathWithin $PreviousReport $allowed)){throw '검토한 탐지 결과가 필요합니다.'}
        Assert-NoReparse $PreviousReport
        if((Get-FileHash -LiteralPath $PreviousReport -Algorithm SHA256).Hash -ine $PreviousSHA256){throw '탐지 결과가 변경되었습니다. 다시 탐지해 주세요.'}
        $prior=ReadJson $PreviousReport
        if($prior.TargetSID -cne $sid -or $prior.Mode -ne 'Detect' -or ([datetimeoffset]::Now-[datetimeoffset]::Parse($prior.At)).TotalHours -gt 24){throw '같은 사용자에 대한 24시간 이내 탐지 결과가 필요합니다.'}
        $approval=Join-Path $JobRoot 'reviewed-engine-actions.json';Save-Json $approval @($prior.RepairPlan)
    }
    Stage $(if($Mode -eq 'Repair'){'알려진 위협 차단·백업·격리 및 재검사'}else{'DLL·Lua·레지스트리·현재 연결·설치 프로그램 검사'}) 10
    $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$engine=Join-Path $root 'engine\Invoke-NikkeRecovery.ps1';$token=[guid]::NewGuid().ToString('N')
    $arg=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$engine+'"'),'-Mode',$(if($Mode -eq 'Repair'){'Apply'}else{'Audit'}),'-TargetProfile',('"'+$TargetProfile+'"'),'-OutputRoot',('"'+(Join-Path $JobRoot 'engine')+'"'),'-RunToken',$token)
    if($approval){$arg+=@('-ApprovedActionsPath',('"'+$approval+'"'))}
    $child=Start-Process -FilePath $ps -ArgumentList $arg -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $JobRoot 'engine.stdout.txt') -RedirectStandardError (Join-Path $JobRoot 'engine.stderr.txt');$handle=$child.Handle;$clock=[Diagnostics.Stopwatch]::StartNew();$beats=0
    while(-not $child.WaitForExit(1000)){$beats++;if($beats%15 -eq 0){Write-CRLog $log ('검사 엔진 실행 중 · 경과 '+[int]$clock.Elapsed.TotalSeconds+'초')};if($Mode -eq 'Detect' -and $clock.Elapsed.TotalMinutes -gt 12){$child.Kill();throw '탐지 엔진 제한 시간 초과. 일부 항목은 검사되지 않았습니다.'}}
    $exit=$child.ExitCode;$child.Dispose()
    $runs=@(Get-ChildItem -LiteralPath (Join-Path $JobRoot 'engine') -Directory|Where-Object {$_.Name.EndsWith('-'+$token)})
    if($runs.Count -ne 1 -or -not(Test-Path -LiteralPath (Join-Path $runs[0].FullName 'summary.json'))){throw ('검사 엔진이 결과를 만들지 못했습니다. 종료 코드 '+$exit)}
    $dir=$runs[0].FullName;$summary=ReadJson (Join-Path $dir 'summary.json');$state=ReadJson (Join-Path $dir 'after.json');$inventory=ReadJson (Join-Path $dir 'post-recovery-inventory.json');$plan=@(ReadJson (Join-Path $dir 'plan.json'))
    if($summary.RunToken -cne $token -or $summary.TargetSID -cne $sid){throw '엔진 결과와 요청이 일치하지 않습니다.'}
    $findings=New-Object 'Collections.Generic.List[object]'
    foreach($dll in $state.DllCandidates){if($dll.Verdict -in @('Confirmed','StrongMatch')){$s=if($dll.Path -match '(?i)\.dll$'){'ConfirmedThreat'}else{'Review'};$findings.Add((New-CRFinding '현재 위협' $s '악성 DLL 지표' $dll.Reason $dll.Path))}}
    foreach($r in $state.Registry){if($r.Disposition -in @('MatchedIncidentOverride','EmptyIncidentOverride')){$findings.Add((New-CRFinding '현재 위협' 'ConfirmedThreat' 'Chrome COM 등록 변조' $r.Disposition $r.Path))}}
    foreach($m in $state.MappedDlls){$findings.Add((New-CRFinding '현재 위협' 'ConfirmedThreat' ('프로세스에 DLL 적재: '+$m.Name) '파일 격리 후에도 메모리에 남을 수 있습니다. 작업을 저장하고 해당 앱을 완전히 종료한 뒤 다시 탐지해야 합니다. 자동으로 앱을 종료하지 않습니다.' $m.Path '' ([string]$m.PID)))}
    foreach($r in $inventory.ConfirmedReferences){$findings.Add((Get-CRInventoryReferenceFinding $r $Mode $plan @($summary.Outcomes)))}
    foreach($l in $summary.LuaFindings){$findings.Add((New-CRFinding 'Lua' 'Review' 'Lua 샘플 또는 구조 지표' '분석 자료·격리본인지 실제 실행 경로인지 확인해야 합니다. 존재만으로 실행·유출을 확정하지 않습니다.' ([string](Get-CRField $l 'Path' ''))))}
    foreach($i in $summary.Issues){$findings.Add((New-CRFinding '검사 범위' 'CoverageGap' $i.Area $i.Message))}
    if($summary.ProcessCoverage.ReadErrors -or $summary.ProcessCoverage.EmptyModuleLists){$findings.Add((New-CRFinding '검사 범위' 'CoverageGap' '일부 프로세스 모듈 미검사' ('읽기 실패 '+$summary.ProcessCoverage.ReadErrors+'개, 빈 모듈 목록 '+$summary.ProcessCoverage.EmptyModuleLists+'개. 관리자 탐지에서도 보호 프로세스는 제한될 수 있습니다.')))}
    Stage '과거 실행·통신·서비스 설치 기록 및 추가 실행 관계 조사' 55
    $launcherRoots=@($state.LauncherPrograms|ForEach-Object {Split-Path $_ -Parent}|Sort-Object -Unique)
    $history=Get-CRHistory $TargetProfile $launcherRoots $EvidenceRoot;Save-Json (Join-Path $JobRoot 'history.json') $history
    foreach($f in $history.Findings){$findings.Add($f)}
    Stage '사용자 설정·정적 탈취 대상·전송 증거 대조' 75
    $settings=Get-CRSettings $sid $TargetProfile;Save-Json (Join-Path $JobRoot 'settings.json') $settings
    foreach($f in $settings.Findings){$findings.Add($f)}
    $transfers=@();if($HarPath){try{$transfers=@(Read-CRHarTransfers $HarPath)}catch{$findings.Add((New-CRFinding '검사 범위' 'CoverageGap' 'HTTP 기록 확인 실패' $_.Exception.Message))}}
    Save-Json (Join-Path $JobRoot 'transfers-redacted.json') $transfers
    $exposure=@(Get-CRExposureCatalog $TargetProfile ([bool]$history.AgentEvidence) $transfers $history.Staging)
    foreach($f in $exposure){$findings.Add($f)}
    if($Mode -eq 'Repair'){
        Stage '승인된 설정 복구와 백업·사후 확인' 88
        $backup=Join-Path $JobRoot 'settings-backup';New-ProtectedDirectory $backup $sid
        foreach($f in @(Repair-CRSettings $sid $TargetProfile $backup @($prior.SettingsPlan))){$findings.Add($f)}
        foreach($o in $summary.Outcomes){$s=if($o.Status -eq 'Completed'){'Repaired'}elseif($o.Status -eq 'Failed'){'Failed'}else{'Review'};$findings.Add((New-CRFinding '복구 결과' $s ('엔진 조치 #'+$o.Id+' · '+$o.Status) '보존본과 조치 상세는 엔진 actions.jsonl 및 summary.json에 기록됩니다.' $dir))}
    }
    $rows=$findings.ToArray();$threats=@($rows|Where-Object Status -eq 'ConfirmedThreat').Count;$confirmed=@($rows|Where-Object Status -eq 'ConfirmedExfiltration').Count;$review=@($rows|Where-Object {$_.Status -in @('Review','CoverageGap','CollectionTrace','CapturedTransfer','Failed')}).Count
    $result=[ordered]@{Version='0.4.4-preview';At=(Get-Date -Format o);Mode=$Mode;TargetProfile=$TargetProfile;TargetSID=$sid;Administrator=$admin;WholeHostCleanClaim=$false;CompleteExfiltrationHistory=$false;ThreatCount=$threats;ConfirmedExfiltrationCount=$confirmed;CapturedTransferCount=@($rows|Where-Object Status -eq 'CapturedTransfer').Count;ReviewCount=$review;RepairableCount=($plan.Count+$settings.Plans.Count);InstalledProgramCount=@($inventory.InstalledPrograms).Count;StartupRelationshipCount=@($inventory.LaunchRelationships).Count;EngineExitCode=$exit;EngineDirectory=$dir;EngineVerdict=$summary.Verdict;AgentExecutionTrace=$history.AgentEvidence;AgentStartedTrace=$history.AgentStartedTrace;AgentStartupFailedTrace=$history.AgentStartupFailedTrace;RepairPlan=$plan;SettingsPlan=$settings.Plans;Rows=$rows;EvidenceDirectory=$JobRoot;Limitations=@('0개는 유출 없음이나 완전 복구를 뜻하지 않습니다.','제공된 HTTP 기록은 진위·수집 PC가 별도로 검증되지 않아 주황색 전송 기록으로만 표시합니다. 이 버전은 HAR만으로 실제 유출을 자동 확정하지 않습니다.','정적 분석은 확인한 Lua와 확보한 DLL에 한정됩니다. 정확한 로컬 Lua 및 당시 악성 l.js는 확보되지 않았습니다.','임의 exec로 설치된 미지의 악성코드, 삭제 로그, 커널·펌웨어, 모든 프로그램 변조는 이 도구로 배제할 수 없습니다.','추가 프로그램은 신뢰할 원본·버전·기준점 없이 자동 정상화하지 않습니다. 계정·토큰·세션 폐기는 별도로 해야 합니다.')}
    $fileState=@{};foreach($f in $inventory.ReferencedFiles){$fileState[$f.Path]=$f.Disposition}
    $result['Programs']=@($inventory.InstalledPrograms|Select-Object Name,Version,Publisher,Location)
    $result['Relationships']=@(foreach($l in $inventory.LaunchRelationships){$p=[string](Get-CRField $l 'FilePath' '');[pscustomobject]@{Kind=$l.Kind;Name=$l.Name;FilePath=$p;Source=$l.Source;FileStatus=$(if(-not $p){'경로 해석 안 됨'}elseif($fileState.ContainsKey($p)){switch($fileState[$p]){'KnownIncidentHash'{'알려진 악성 해시'}'InventoryOnly'{'해시 기록 · 정상 보증 아님'}'ReferencedFileMissing'{'참조 파일 없음'}'Over64MiBLimit'{'크기 제한 · 미검사'}default{'읽기 실패·미검사'}}}else{'한도·접근 제한 · 미검사'})}})
    Save-Json $reportPath $result
    $html=New-Object Text.StringBuilder;[void]$html.Append('<!doctype html><meta charset="utf-8"><title>NikkeCR 결과</title><style>body{font:15px Segoe UI,sans-serif;background:#101724;color:#e8edf6;padding:32px}table{border-collapse:collapse;width:100%}td,th{text-align:left;border-bottom:1px solid #394458;padding:10px}.ConfirmedExfiltration{color:#ff7676}.ConfirmedThreat,.PotentialExposure,.CollectionTrace,.CapturedTransfer{color:#ffd28a}.Repaired{color:#87dca1}</style><h1>NikkeCR 검사 결과</h1><p>0개는 안전 또는 유출 없음의 증명이 아닙니다. 결과에는 검사하지 못한 범위가 포함됩니다.</p><table><tr><th>분류</th><th>상태</th><th>항목</th><th>근거·한계</th></tr>')
    foreach($r in $rows){$encode=[System.Net.WebUtility];[void]$html.Append(('<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f $encode::HtmlEncode($r.Status),$encode::HtmlEncode($r.Category),$encode::HtmlEncode((Get-CRStatusLabel $r.Status)),$encode::HtmlEncode($r.Title),$encode::HtmlEncode($r.Reason)))}
    [void]$html.Append('</table>');[IO.File]::WriteAllText((Join-Path $JobRoot 'report.html'),$html.ToString(),(New-Object Text.UTF8Encoding($false)))
    Write-CRLog $log ('완료 · 현재 위협 '+$threats+' / 전송 증거 '+$confirmed+' / 추가 확인 '+$review+' · 전체 안전 판정 아님')
    Save-Json $statusPath @{Stage='완료 · 검사 범위와 추가 확인 항목을 확인하세요';Percent=100;Finished=$true;Success=$true;Report=$reportPath}
    exit $exit
}catch{
    Write-CRLog $log ('중단 · '+$_.Exception.Message);Save-Json $statusPath @{Stage='실패 · 안전 판정 불가';Percent=0;Finished=$true;Success=$false;Error=(Protect-CRText $_.Exception.Message)};exit 3
}

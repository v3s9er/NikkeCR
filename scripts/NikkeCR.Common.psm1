Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot '..\engine\NikkeRecovery.Core.psm1') -DisableNameChecking
function Get-CRField($Object,[string]$Name,$Default=$null){if($null -ne $Object -and $Object.PSObject.Properties[$Name]){return $Object.$Name};return $Default}
function Get-CRHash([string]$Text){$s=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Protect-CRText([string]$Text){
    $Text=[regex]::Replace($Text,'(?i)("(?:authorization|password|passwd|token|api[_-]?key|secret|agent_pass)"\s*:\s*)"(?:[^"\\]|\\.)*"','$1"<redacted>"')
    $t=[regex]::Replace($Text,'(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|(?:password|passwd|token|api[_-]?key|secret|agent_pass)\s*[:=]\s*)[^\s,;]+','$1<redacted>')
    $t=[regex]::Replace($t,'(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,})\b','<redacted>')
    return $t
}
function Write-CRLog([string]$Path,[string]$Message){$line='['+(Get-Date -Format 'HH:mm:ss')+'] '+(Protect-CRText $Message);[IO.File]::AppendAllText($Path,$line+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)));Write-Host $line}
function Read-CRText([string]$Path,[long]$MaxBytes=33554432){
    Assert-NoReparse $Path;$f=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($f.PSIsContainer -or $f.Length -gt $MaxBytes -or ([int]$f.Attributes -band (0x1000 -bor 0x40000 -bor 0x400000))){throw 'Unreadable, oversized or cloud placeholder artifact'}
    $stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try{$r=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true);try{return $r.ReadToEnd()}finally{$r.Dispose()}}finally{$stream.Dispose()}
}
function Find-CRFiles([string[]]$Roots,[string[]]$Names=@('*'),[int]$MaxFiles=5000,[int]$MaxDepth=8,[int]$Seconds=30){
    $rows=New-Object 'Collections.Generic.List[string]';$errors=New-Object 'Collections.Generic.List[string]';$q=New-Object 'Collections.Generic.Queue[object]';$watch=[Diagnostics.Stopwatch]::StartNew();$visited=0;$truncated=$false
    foreach($root in $Roots){if($root -and (Test-Path -LiteralPath $root)){try{Assert-NoReparse $root;$q.Enqueue(@($root,0))}catch{$errors.Add('Root skipped: '+$root)}}}
    while($q.Count){if($visited -ge $MaxFiles -or $watch.Elapsed.TotalSeconds -ge $Seconds){$truncated=$true;break};$node=$q.Dequeue();try{
        foreach($f in @(Get-ChildItem -LiteralPath $node[0] -Force -ErrorAction Stop)){
            $visited++;if($visited -gt $MaxFiles -or $watch.Elapsed.TotalSeconds -ge $Seconds){$truncated=$true;break}
            if(([int]$f.Attributes -band (0x400 -bor 0x1000 -bor 0x40000 -bor 0x400000))){$truncated=$true;continue}
            if($f.PSIsContainer){if($node[1] -lt $MaxDepth){$q.Enqueue(@($f.FullName,([int]$node[1]+1)))}else{$truncated=$true}}else{foreach($pattern in $Names){if($f.Name -like $pattern){$rows.Add($f.FullName);break}}}
        }
    }catch{$errors.Add('Directory unreadable: '+[string]$node[0])}}
    return [pscustomobject]@{Files=@($rows.ToArray()|Sort-Object -Unique);Errors=$errors.ToArray();Truncated=$truncated;Visited=$visited}
}
function New-CRFinding([string]$Category,[string]$Status,[string]$Title,[string]$Reason,[string]$Source='', [string]$At='', [string]$Target=''){
    return [pscustomobject]@{Id=(Get-CRHash ($Category+'|'+$Status+'|'+$Title+'|'+$Source+'|'+$At+'|'+$Target));Category=$Category;Status=$Status;Title=$Title;Reason=(Protect-CRText $Reason);Source=$Source;At=$At;Target=$Target}
}
function Get-CRInventoryReferenceFinding($Reference,[string]$Mode,[object[]]$Plan,[object[]]$Outcomes){
    $source=[string]$Reference.Path;$quarantined=$false
    if($Mode -eq 'Repair'){
        foreach($action in @($Plan|Where-Object {$_.Kind -eq 'QuarantineDll' -and $_.Target -ceq $source})){
            foreach($outcome in @($Outcomes|Where-Object {$_.Id -eq $action.Id -and $_.Status -eq 'Completed'})){
                $detail=$outcome.Detail
                if($detail -and $action.Extra.SHA256 -match '^[a-fA-F0-9]{64}$' -and $detail.SHA256 -ieq $action.Extra.SHA256 -and $detail.Preserved -and (Get-CRField $detail 'OriginalStillExists' $true) -eq $false -and -not(Test-Path -LiteralPath $source)){
                    try{Assert-NoReparse $detail.Preserved;if((Get-FileHash -LiteralPath $detail.Preserved -Algorithm SHA256 -ErrorAction Stop).Hash -ieq $detail.SHA256){$quarantined=$true}}catch{}
                }
            }
        }
    }
    if($quarantined){return (New-CRFinding '프로그램·설정' 'Repaired' '추가 위치의 사건 DLL 격리됨' '검사 중 발견한 파일을 백업·격리하고 원래 경로가 사라진 것을 확인했습니다.' $source)}
    return (New-CRFinding '프로그램·설정' 'Review' '추가 위치에서 사건 지표 발견' ([string]$Reference.Reason) $source)
}
function Get-CRStatusLabel([string]$Status){switch($Status){'ConfirmedExfiltration'{'실제 유출 확인'}'CapturedTransfer'{'전송 기록 · PC 귀속 미확인'}'ConfirmedThreat'{'알려진 위협'}'PotentialExposure'{'노출 가능'}'CollectionTrace'{'수집 흔적 · 유출 미확정'}'Review'{'추가 확인 필요'}'CapabilityOnly'{'악성 기능 확인 · 실행 미확정'}'NotObserved'{'현재 흔적 미확인'}'CoverageGap'{'검사하지 못함'}'Repaired'{'복구 후 확인'}'Failed'{'복구 실패'}default{$Status}}}
function Assert-CRPackage([string]$Root){
    $manifest=Join-Path $Root 'NikkeCR-SHA256.json';$m=Read-CRText $manifest 1MB|ConvertFrom-Json
    if($m.Version -ne '0.4.4-preview' -or @($m.Files).Count -lt 10){throw 'Unsupported or incomplete package manifest'}
    foreach($f in $m.Files){if($f.Path -match '(^[\\/]|\.\.|:)' -or $f.SHA256 -notmatch '^[a-f0-9]{64}$'){throw 'Invalid manifest entry'};$p=Join-Path $Root $f.Path;Assert-NoReparse $p;if((Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash -ine $f.SHA256){throw ('Package mismatch: '+$f.Path)}}
}
Export-ModuleMember -Function *-CR*

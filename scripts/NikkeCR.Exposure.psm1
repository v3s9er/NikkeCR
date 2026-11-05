Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.Common.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot '..\engine\NikkeRecovery.Core.psm1') -DisableNameChecking
function Get-CRExposureCatalog([string]$Profile,[bool]$AgentEvidence,[object[]]$Transfers=@(),[object[]]$Staging=@()){
    $catalog=Read-CRText (Join-Path $PSScriptRoot '..\data\static-capabilities.json')|ConvertFrom-Json
    $rows=New-Object 'Collections.Generic.List[object]';$meta=New-Object 'Collections.Generic.List[object]'
    foreach($group in @($catalog.Targets|Group-Object tool)){
        $found=New-Object 'Collections.Generic.List[string]';$unknown=0
        foreach($item in $group.Group){foreach($pattern in $item.paths){
            $p=[string]$pattern;$p=$p.Replace('\\','\');$p=$p.Replace('~',$Profile)
            $p=$p.Replace('%APPDATA%',(Join-Path $Profile 'AppData\Roaming')).Replace('%LOCALAPPDATA%',(Join-Path $Profile 'AppData\Local')).Replace('%USERPROFILE%',$Profile)
            if($p -match '^\$|\$\{|%|\{'){ $unknown++;continue }
            if($p -notmatch '^[A-Za-z]:\\' -or $p -match '[\r\n]'){ $unknown++;continue }
            try{
                $base=$p;while($base -match '[*?]'){$base=Split-Path $base -Parent};if($base){Assert-NoReparse $base}
                foreach($f in @(Get-Item -Path $p -Force -ErrorAction Stop|Select-Object -First 30)){
                    if(([int]$f.Attributes -band (0x400 -bor 0x1000 -bor 0x40000 -bor 0x400000))){$unknown++;continue};Assert-NoReparse $f.FullName;$found.Add($f.FullName)
                }
            }catch [System.Management.Automation.ItemNotFoundException]{}catch{$unknown++}
        }}
        $status='CapabilityOnly';$reason='정적 분석에서 수집 경로 확인. 현재 파일 내용이나 자격증명 값은 읽지 않음.'
        if($found.Count){$status='PotentialExposure';$reason=('대상 경로 '+$found.Count+'개 존재. 실제 수집·전송 여부는 미확정. '+$(if($AgentEvidence){'이 PC의 에이전트 실행 흔적 있음.'}else{'이 검사에서 에이전트 실행 여부 미확정.'}))}
        if($unknown){$reason+=' 확인하지 못한 경로/환경 변수 '+$unknown+'개.'}
        $row=New-CRFinding '개발·클라우드 계정' $status $group.Name $reason 'Lua keyscan: L139-L208';$row|Add-Member NoteProperty Paths @($found.ToArray()|Sort-Object -Unique);$rows.Add($row)
    }
    foreach($item in @(
        @('브라우저 로그인 정보','Chromium Login Data·Local State, Firefox logins.json·key4.db. 암호문과 복호화 관련 자료 수집 경로.','Lua L214-L232'),
        @('브라우저 쿠키·세션','쿠키 수집 기능. 로컬 옵션과 빌드 차이가 있어 기능 존재만으로 수집을 확정하지 않음.','Lua L214-L232'),
        @('NIKKE 저장 로그인','런처 저장 계정의 복호화를 시도하는 기능. 실제 사용자 비밀번호는 복호화하지 않음.','Lua L242-L255'),
        @('화면 캡처','화면 이미지 수집. 웹캠·마이크 녹음으로 확대 해석하지 않음.','Lua L057-L066'),
        @('시스템·사용자 정보','컴퓨터·사용자·권한·시스템 정보 조회. 조회 기능과 실제 전송은 구분.','Lua L256-L266'),
        @('임의 파일·명령 출력','cat/download/exec로 접근 가능한 파일과 명령 출력. 고정 경로 목록이 접근 범위의 상한은 아님.','Lua commands.cat/download/exec'),
        @('추가 자격증명 수집기','환경 변수·명령 기록·Kubernetes·Windows 자격증명·FileZilla·프로젝트 설정·PuTTY/WinSCP·GPG 메타데이터 등. 일부는 메타데이터만 수집.','Lua keyscan additional collectors')
    )){$rows.Add((New-CRFinding '기타 탈취 대상' 'CapabilityOnly' $item[0] $item[1] $item[2]))}
    $extensions=Join-Path $Profile 'AppData\Local\Google\Chrome\User Data';$profiles=@();if(Test-Path -LiteralPath $extensions){$profiles=@(Get-ChildItem -LiteralPath $extensions -Directory -ErrorAction SilentlyContinue|Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint)-eq 0})}
    foreach($w in $catalog.Wallets){$exists=$false;foreach($p in $profiles){if(Test-Path -LiteralPath (Join-Path $p.FullName ('Extensions\'+$w.extension_id))){$exists=$true;break}}
        $status=if($exists){'PotentialExposure'}else{'CapabilityOnly'};$reason='DLL이 대상으로 삼는 지갑: '+($w.capture_mode_labels -join ', ')+'. 설치 흔적만으로 유출을 확정하지 않음.'
        if(@($Transfers|Where-Object {$_.Wallet -ieq $w.name}).Count){$status='CapturedTransfer';$reason='제공된 HTTP 기록에서 DLL 전송 본문과 성공 응답 확인. 기록의 진위·수집 PC는 미검증이므로 이 PC의 실제 유출로 확정하지 않음. 값은 표시하지 않음.'}
        $rows.Add((New-CRFinding '지갑' $status ([string]$w.name) $reason ('DLL 180001a50 / 180006020 / 18000e030; '+$w.extension_id)))
    }
    foreach($s in $Staging){$rows.Add((New-CRFinding '수집 흔적' 'CollectionTrace' $s.Kind '악성코드의 임시 수집물 이름과 일치. 이름만으로 내용·원격 전송은 확정할 수 없음.' $s.Path $s.At))}
    foreach($t in $Transfers|Where-Object {-not $_.Wallet}){$rows.Add((New-CRFinding '전송 내용' 'CapturedTransfer' ('DLL 전송 항목: '+$t.Kind) '제공된 HTTP 기록의 본문·성공 응답 근거. 진위와 수집 PC가 미검증이므로 실제 유출 확정은 보류. 원문 값 대신 해시만 보관.' $t.Source $t.At))}
    return $rows.ToArray()
}
function Read-CRHarTransfers([string]$Path){
    $har=Read-CRText $Path 33554432|ConvertFrom-Json;$rows=New-Object 'Collections.Generic.List[object]';$catalog=Read-CRText (Join-Path $PSScriptRoot '..\data\static-capabilities.json')|ConvertFrom-Json
    if(@($har.log.entries).Count -gt 10000){throw 'HAR entry limit exceeded'}
    $sourceHash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    foreach($e in @($har.log.entries)){
        try{
            $uri=[uri]$e.request.url
            if($uri.Scheme -ne 'https' -or $uri.DnsSafeHost -ine 'analytics.insightjs.com' -or $uri.AbsolutePath -notmatch '^/px/[a-fA-F0-9]{32}/?$' -or $e.request.method -cne 'POST'){continue}
            if([int]$e.response.status -lt 200 -or [int]$e.response.status -ge 300){continue}
            $post=$e.request.postData.text|ConvertFrom-Json
            if((@($post.PSObject.Properties.Name|Sort-Object) -join ',') -cne 'kind,value'){continue}
            if($post.kind -isnot [string] -or $post.value -isnot [string] -or [string]::IsNullOrWhiteSpace($post.value) -or $post.kind.Length -gt 100){continue}
            $when=[datetimeoffset]::Parse($e.startedDateTime).ToString('o');$wallet=$null
            foreach($w in $catalog.Wallets){if($post.kind -ieq $w.name -or $post.kind.StartsWith(([string]$w.name+':'),[StringComparison]::OrdinalIgnoreCase)){$wallet=[string]$w.name;break}}
            $rows.Add([pscustomobject]@{At=$when;Kind=$(if($wallet){$wallet}else{'종류 미분류'});KindSHA256=(Get-CRHash $post.kind);Wallet=$wallet;ValueSHA256=(Get-CRHash $post.value);Source=$Path;SourceSHA256=$sourceHash;Evidence='Provided HAR request and 2xx response; capture authenticity and capture host are not independently established';RemoteRetentionProven=$false})
        }catch{}
    };return $rows.ToArray()
}
Export-ModuleMember -Function Get-CRExposureCatalog,Read-CRHarTransfers

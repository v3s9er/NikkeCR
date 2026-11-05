Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.Common.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeCR.History.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot '..\engine\NikkeRecovery.Core.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot '..\engine\NikkeRecovery.PostRecovery.psm1') -DisableNameChecking
function Get-CRSettings([string]$Sid,[string]$Profile){
    if($Sid -notmatch '^S-1-5-21-[0-9-]+$'){throw 'Invalid target SID'}
    $rows=New-Object 'Collections.Generic.List[object]';$plans=New-Object 'Collections.Generic.List[object]';$coverage=New-Object 'Collections.Generic.List[object]'
    $base='Registry::HKEY_USERS\'+$Sid+'\Software\';$machine='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\'
    $paths=@('Microsoft\Windows\CurrentVersion\Run','Microsoft\Windows\CurrentVersion\RunOnce','Microsoft\Windows\CurrentVersion\Internet Settings','Policies\Google\Chrome','Policies\Microsoft\Edge','Microsoft\Windows NT\CurrentVersion\Winlogon')
    foreach($prefix in @($base,$machine)){foreach($relative in $paths){$path=$prefix+$relative;try{
        if(-not(Test-Path -LiteralPath $path)){continue};$key=Get-Item -LiteralPath $path -ErrorAction Stop
        foreach($name in $key.GetValueNames()){$value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);$text=[string]($value -join ' ');$kind=[string]$key.GetValueKind($name)
            if(-not(Test-CRIndicator $text)){continue}
            $reason='설정 값에 사건 지표가 포함됨. 원문은 보호된 로컬 검사 결과에만 보관하며 자동 삭제하지 않음.';$eligible=$false
            if($prefix -eq $base -and $relative -eq 'Microsoft\Windows\CurrentVersion\Internet Settings' -and $name -eq 'AutoConfigURL' -and $kind -eq 'String'){
                try{$uri=[uri]$text;if($uri.Scheme -in @('http','https') -and $uri.DnsSafeHost -in @('insightjs.com','analytics.insightjs.com','insightjs.org')){$eligible=$true;$reason='알려진 공격자 도메인을 PAC 설정으로 사용. 백업 후 해당 값만 제거할 수 있음.'}}catch{}
            }
            if($prefix -eq $base -and $relative -in @('Microsoft\Windows\CurrentVersion\Run','Microsoft\Windows\CurrentVersion\RunOnce')){
                try{$exe=Get-ProgramCommandPath $text $Profile;if($exe){Assert-NoReparse $exe;if((Get-FileHash -LiteralPath $exe -Algorithm SHA256 -ErrorAction Stop).Hash -ieq '10e722777685e290e8fd5370d4c5cd1a40d0d7e91b93af0156faefe18467a3f1'){$eligible=$true;$reason='자동 실행 값이 알려진 악성 DLL 해시의 파일을 직접 참조. 백업 후 이 값만 제거 가능.'}}}catch{}
            }
            $row=New-CRFinding '프로그램·설정' 'Review' ($relative+' / '+$name) $reason $path '' $name;$rows.Add($row)
            if($eligible){$plans.Add([pscustomobject]@{Id=$row.Id;Path=$path;Name=$name;Value=$value;Kind=$kind;ValueHash=(Get-CRHash ($kind+'|'+($value|ConvertTo-Json -Compress)));Reason=$reason})}
        };$coverage.Add([pscustomobject]@{Path=$path;Status='Read'})
    }catch{$rows.Add((New-CRFinding '검사 범위' 'CoverageGap' $relative '레지스트리 설정을 읽지 못함.' $path))}}}
    return [pscustomobject]@{Findings=$rows.ToArray();Plans=$plans.ToArray();Coverage=$coverage.ToArray()}
}
function Repair-CRSettings([string]$Sid,[string]$Profile,[string]$BackupRoot,[object[]]$ExpectedPlans){
    Assert-NoReparse $BackupRoot;$fresh=Get-CRSettings $Sid $Profile;$results=New-Object 'Collections.Generic.List[object]'
    foreach($expected in $ExpectedPlans){$id=$expected.Id;$matches=@($fresh.Plans|Where-Object {$_.Id -eq $id -and $_.ValueHash -ceq $expected.ValueHash -and $_.Path -ceq $expected.Path -and $_.Name -ceq $expected.Name});if($matches.Count -ne 1){$results.Add((New-CRFinding '복구 결과' 'Failed' '설정 복구 제외' '현재 값이 승인한 복구 조건과 일치하지 않음.' '' '' $id));continue}
        $p=$matches[0];try{
            $key=Get-Item -LiteralPath $p.Path -ErrorAction Stop;$now=$key.GetValue($p.Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if((Get-CRHash ([string]$key.GetValueKind($p.Name)+'|'+($now|ConvertTo-Json -Compress))) -cne $p.ValueHash){throw 'Setting changed before backup'}
            $backup=Join-Path $BackupRoot ($id+'.registry-value.json');if(Test-Path -LiteralPath $backup){throw 'Backup collision'}
            Save-Json $backup $p;$read=Read-CRText $backup|ConvertFrom-Json
            if($read.ValueHash -cne $p.ValueHash -or (Get-CRHash ($read.Kind+'|'+($read.Value|ConvertTo-Json -Compress))) -cne $p.ValueHash){throw 'Backup verification failed'}
            $key=Get-Item -LiteralPath $p.Path -ErrorAction Stop;$now=$key.GetValue($p.Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if((Get-CRHash ([string]$key.GetValueKind($p.Name)+'|'+($now|ConvertTo-Json -Compress))) -cne $p.ValueHash){throw 'Setting changed after backup'}
            $prefix='Registry::HKEY_USERS\'+$Sid+'\'
            if(-not $p.Path.StartsWith($prefix,[StringComparison]::Ordinal)){throw 'User registry boundary mismatch'}
            $writable=[Microsoft.Win32.Registry]::Users.OpenSubKey($p.Path.Substring('Registry::HKEY_USERS\'.Length),$true)
            if($null -eq $writable){throw 'Registry value is not writable'}
            try{$writable.DeleteValue($p.Name,$true)}finally{$writable.Dispose()}
            if($p.Name -in (Get-Item -LiteralPath $p.Path).GetValueNames()){throw 'Post-verification failed'}
            $results.Add((New-CRFinding '복구 결과' 'Repaired' ('설정 값 제거: '+$p.Name) '현재 값 재검증 → 백업 내용 검증 → 값 제거 → 제거 확인 완료.' $backup))
        }catch{$results.Add((New-CRFinding '복구 결과' 'Failed' ('설정 복구: '+$p.Name) $_.Exception.Message $p.Path))}
    };return $results.ToArray()
}
Export-ModuleMember -Function Get-CRSettings,Repair-CRSettings

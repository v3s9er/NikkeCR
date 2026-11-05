Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.FollowUp.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Integrity.psm1') -DisableNameChecking
function Get-AftercareField($Object,[string]$Name,$Default=$null) {
    if($null -ne $Object -and $Object.PSObject.Properties[$Name]){return $Object.$Name};return $Default
}
function Get-AftercareTextHash([string]$Text) {
    $h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
}
function Initialize-NikkeAftercareState([string]$Path,[string]$UserSid) {
    $root=Get-CanonicalPath $Path;Assert-NoReparse $root
    if($root.Length -le 3){throw 'A dedicated aftercare directory is required'}
    foreach($reserved in @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:USERPROFILE,$env:LOCALAPPDATA,$env:APPDATA,$env:ProgramData,$PSScriptRoot)){
        if($reserved -and $root -ieq (Get-CanonicalPath $reserved)){throw 'Broad/system/tool directory refused for aftercare state'}
    }
    if((Test-PathWithin $root $env:SystemRoot) -or (Test-PathWithin $root $PSScriptRoot)){throw 'Aftercare evidence must be separate from Windows and the tool package'}
    $marker=Join-Path $root 'aftercare-owner.json'
    if(Test-Path -LiteralPath $root){
        if(-not(Test-Path -LiteralPath $marker)){
            if(@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop).Count){throw 'Existing nonempty directory is not an initialized aftercare store'}
        }else{
            Assert-NoReparse $marker;if((Get-Item -LiteralPath $marker).Length -gt 4096){throw 'Invalid aftercare ownership marker'}
            $owner=Get-Content -Encoding UTF8 -Raw -LiteralPath $marker|ConvertFrom-Json
            if($owner.Kind -ne 'NikkeAftercareState' -or $owner.UserSid -ne $UserSid){throw 'Aftercare store belongs to another identity'}
        }
    }
    New-ProtectedDirectory $root $UserSid
    if(-not(Test-Path -LiteralPath $marker)){Save-Json $marker ([pscustomobject]@{Kind='NikkeAftercareState';UserSid=$UserSid;Schema=1})}
}
function New-NikkeAftercareAssessment($Summary,$Inventory,$PreviousSummary=$null,$PreviousInventory=$null,[string]$BootId='',[string]$PreviousBootId='',[object[]]$IntegrityPlans=@(),[object[]]$PendingChanges=@()) {
    $changes=@();$comparison=$null
    if($null -ne $PreviousInventory){
        if((Get-AftercareField $PreviousInventory 'TargetSid' '') -cne (Get-AftercareField $Inventory 'TargetSid' '')){throw 'Cannot compare different user inventories'}
        $comparison=Compare-RecoveryInventories $PreviousInventory $Inventory;$changes=@($comparison.Changes)
    }
    $pending=@{}
    foreach($change in @($PendingChanges)+@($changes)){$id=Get-AftercareTextHash (ConvertTo-Json $change -Depth 14 -Compress);$pending[$id]=$change}
    if($pending.Count -gt 5000){throw 'Pending-change ledger exceeds limit; review existing changes before continuing'}
    $openChanges=@($pending.Keys|Sort-Object|ForEach-Object{$pending[$_]})
    $coverage=Get-AftercareField $Inventory 'Coverage'
    $process=Get-AftercareField $Summary 'ProcessCoverage'
    $complete=([bool](Get-AftercareField $Inventory 'WorkerCompleted' $false) -and @(Get-AftercareField $Inventory 'Errors' @()).Count -eq 0 -and [int](Get-AftercareField $coverage 'MissingOrUnexaminedFiles' 1) -eq 0 -and [int](Get-AftercareField $coverage 'UnresolvedCommandsOrShortcuts' 1) -eq 0 -and [int](Get-AftercareField $process 'ReadErrors' 1) -eq 0 -and [int](Get-AftercareField $process 'EmptyModuleLists' 1) -eq 0 -and @(Get-AftercareField $Summary 'Issues' @()).Count -eq 0)
    $known=[int](Get-AftercareField $Summary 'RemainingKnownActiveIndicators' 0)
    $mapped=@(Get-AftercareField $Summary 'MappedDllProcesses' @()).Count
    $references=@(Get-AftercareField $Inventory 'ConfirmedReferences' @()).Count
    $integrityFindings=@();foreach($plan in $IntegrityPlans){foreach($file in @($plan.Files|Where-Object Status -ne 'Match')){$integrityFindings += [pscustomobject]@{Root=$plan.TargetRoot;RelativePath=$file.RelativePath;Status=$file.Status;SHA256=$file.CurrentSHA256}};foreach($file in @($plan.UnlistedBinaries)){$integrityFindings += [pscustomobject]@{Root=$plan.TargetRoot;RelativePath=$file.RelativePath;Status=$file.Status;SHA256=$null}};if(-not $plan.CoverageComplete){$complete=$false}}
    $severity='Observed';if(-not $complete -or $openChanges.Count -or $references -or $integrityFindings.Count -or (Get-AftercareField $Summary 'Verdict' '') -eq 'ReviewRequired'){$severity='ReviewRequired'}
    if($known -or $mapped){$severity='KnownIndicatorsRemain'}
    $reboot=($BootId -and $PreviousBootId -and $BootId -cne $PreviousBootId)
    $recurrence='NoPostBootComparison'
    if($reboot){if($known -or $mapped){$recurrence='KnownIndicatorsAfterRestart'}elseif($severity -eq 'ReviewRequired'){$recurrence='InconclusiveAfterRestart'}else{$recurrence='NoKnownIndicatorsAfterRestartWithinScope'}}
    $fingerprint=[ordered]@{Severity=$severity;Known=$known;Mapped=$mapped;References=$references;CoverageComplete=$complete;PendingChanges=$openChanges;Integrity=$integrityFindings}
    return [pscustomobject]@{Schema=1;At=(Get-Date -Format o);Severity=$severity;KnownIndicators=$known;MappedDlls=$mapped;IncidentReferences=$references;CoverageComplete=$complete;Changes=$changes;PendingChanges=$openChanges;IntegrityFindings=$integrityFindings;BaselineChecks=$IntegrityPlans.Count;BootId=$BootId;NewBootObserved=[bool]$reboot;Recurrence=$recurrence;AlertSignature=(Get-AftercareTextHash (ConvertTo-Json $fingerprint -Depth 14 -Compress));WholeHostCleanClaim=$false;ReadOnly=$true;AutomaticRepair=$false;Interpretation='Changes require review; no change is not proof of integrity. Missing or partial observations cannot establish successful recovery.'}
}
function Write-NikkeAftercareDashboard([string]$Path,$Assessment,[string]$ReportDirectory) {
    $safe=[System.Net.WebUtility]::HtmlEncode((ConvertTo-Json $Assessment -Depth 14))
    $report=[System.Net.WebUtility]::HtmlEncode($ReportDirectory)
    $html='<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>NIKKE Recovery Kit — 사후관리</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 24px;background:#10151f;color:#e7edf7}h1{font-size:28px}p{line-height:1.7}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1b2433;padding:20px;border-radius:12px}code{overflow-wrap:anywhere}</style><h1>NIKKE Recovery Kit · 사후관리</h1><p>가장 최근 관찰 결과입니다. 변화는 검토할 단서이며, PC 전체의 안전 판정은 아닙니다. CoverageComplete가 false이면 조사하지 못한 영역이 있습니다.</p><p>KnownIndicatorsRemain: 알려진 흔적이 남음 · ReviewRequired: 추가 확인 필요 · Observed: 이번 범위의 관찰 완료</p><p>결과 위치: <code>'+$report+'</code></p><pre>'+$safe+'</pre></html>'
    [IO.File]::WriteAllText($Path,$html,(New-Object Text.UTF8Encoding($false)))
}
function New-NikkeAftercareTaskXml([string]$ScriptPath,[string]$StateRoot,[string]$UserSid,[int]$Hours=6,[bool]$Notify=$false,[string]$BaselineConfigPath='',[string]$BaselineConfigSHA256='') {
    if($Hours -lt 1 -or $Hours -gt 168 -or $UserSid -notmatch '^S-1-5-21-[0-9-]+$'){throw 'Invalid task interval or user SID'}
    $script=Get-CanonicalPath $ScriptPath;$state=Get-CanonicalPath $StateRoot
    $args='-NoProfile -ExecutionPolicy Bypass -File "'+$script+'" -StateRoot "'+$state+'"'
    if($Notify){$args+=' -Notify'}
    if($BaselineConfigPath){if($BaselineConfigSHA256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Baseline configuration must be pinned'};$args+=' -BaselineConfigPath "'+(Get-CanonicalPath $BaselineConfigPath)+'" -BaselineConfigSHA256 '+$BaselineConfigSHA256}
    $args=[Security.SecurityElement]::Escape($args);$exe=[Security.SecurityElement]::Escape((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))
    $start=(Get-Date).AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ss')
    return '<?xml version="1.0" encoding="UTF-16"?><Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Author>NIKKE Recovery Kit</Author><Description>Read-only NIKKE aftercare; no automatic repair or Defender scan</Description></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>'+$UserSid+'</UserId><Delay>PT3M</Delay></LogonTrigger><TimeTrigger><Repetition><Interval>PT'+$Hours+'H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>'+$start+'</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Principals><Principal id="CurrentUser"><UserId>'+$UserSid+'</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT15M</ExecutionTimeLimit><Enabled>true</Enabled><Hidden>false</Hidden><WakeToRun>false</WakeToRun></Settings><Actions Context="CurrentUser"><Exec><Command>'+$exe+'</Command><Arguments>'+$args+'</Arguments></Exec></Actions></Task>'
}
Export-ModuleMember -Function New-NikkeAftercareAssessment,Write-NikkeAftercareDashboard,New-NikkeAftercareTaskXml,Get-AftercareTextHash,Initialize-NikkeAftercareState

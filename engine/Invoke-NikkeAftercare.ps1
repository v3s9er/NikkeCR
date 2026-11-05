#requires -Version 5.1
[CmdletBinding()]
param([string]$StateRoot=(Join-Path $env:LOCALAPPDATA 'NikkeRecovery\Aftercare'),[switch]$Notify,[string]$BaselineConfigPath='',[string]$BaselineConfigSHA256='',[ValidateRange(60,900)][int]$InspectionTimeoutSeconds=600,[switch]$AcknowledgeChanges,[string]$ExpectedAlertSignature='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Test-NikkePackage.ps1');Assert-NikkePackage $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Integrity.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Aftercare.psm1') -DisableNameChecking
$StateRoot=Get-CanonicalPath $StateRoot;Assert-NoReparse $StateRoot
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$mutex=[Threading.Mutex]::new($false,('Local\NikkeAftercare-'+$sid));$held=$false;$initialized=$false
try {
    try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
    if(-not $held){Write-Output 'Aftercare is already running for this user.';exit 0}
    Initialize-NikkeAftercareState $StateRoot $sid;$initialized=$true
    $token=[guid]::NewGuid().ToString('N');$run=Join-Path $StateRoot ('run-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+$token);New-ProtectedDirectory $run $sid
    $statePath=Join-Path $StateRoot 'latest.json';$previous=$null;$previousSummary=$null;$previousInventory=$null;$priorProblem=$null
    if(Test-Path -LiteralPath $statePath){
        try {
            Assert-NoReparse $statePath
            if((Get-Item -LiteralPath $statePath).Length -gt 8MB){throw 'Invalid previous state size'}
            $previous=Get-Content -Encoding UTF8 -Raw -LiteralPath $statePath|ConvertFrom-Json
            foreach($path in @($previous.SummaryPath,$previous.InventoryPath)){if(-not(Test-PathWithin $path $StateRoot)){throw 'Previous state escaped aftercare directory'}}
            $previousSummary=Read-NikkePinnedJson $previous.SummaryPath $previous.SummarySHA256
            $previousInventory=Read-NikkePinnedJson $previous.InventoryPath $previous.InventorySHA256
            if($previousInventory.TargetSid -ne $sid){throw 'Previous inventory belongs to another user'}
        }catch{$priorProblem=$_.Exception.Message;$previous=$null;$previousSummary=$null;$previousInventory=$null}
    }
    if($AcknowledgeChanges){
        if($null -eq $previous -or $ExpectedAlertSignature -notmatch '^[a-fA-F0-9]{64}$' -or $previous.AlertSignature -ine $ExpectedAlertSignature){throw 'Review the latest report and supply its exact AlertSignature before acknowledging changes'}
        Save-Json (Join-Path $run 'review-acknowledgement.json') ([pscustomobject]@{At=(Get-Date -Format o);PreviousAlertSignature=$previous.AlertSignature;AcknowledgedChanges=$previous.PendingChanges;KnownIndicatorsNotDismissed=$true;WholeHostCleanClaim=$false})
        $previous.PendingChanges=@();Save-NikkeAtomicJson $statePath $previous
        Write-Output 'Snapshot changes acknowledged. Known indicators and integrity findings will still be checked; no files or settings were repaired.';exit 0
    }
    $auditRoot=Join-Path $run 'audit';New-ProtectedDirectory $auditRoot $sid
    $entry=Join-Path $PSScriptRoot 'Invoke-NikkeRecovery.ps1'
    $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$entry+'"'),'-Mode','Verify','-TargetProfile',('"'+(Get-CanonicalPath $env:USERPROFILE)+'"'),'-OutputRoot',('"'+$auditRoot+'"'),'-RunToken',$token)
    $child=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $run 'worker.stdout.txt') -RedirectStandardError (Join-Path $run 'worker.stderr.txt')
    # Retain the process handle before waiting; Windows PowerShell 5.1 can
    # otherwise return a null ExitCode after a short-lived child has exited.
    $retainedHandle=$child.Handle
    if(-not $child.WaitForExit($InspectionTimeoutSeconds*1000)){try{$child.Kill()}catch{};throw 'Read-only aftercare worker timed out; no complete observation is available'}
    $child.WaitForExit()
    if($null -eq $child.ExitCode -or $child.ExitCode -ne 0){throw ('Read-only aftercare worker failed or had no exit receipt: '+$child.ExitCode)}
    $dirs=@(Get-ChildItem -LiteralPath $auditRoot -Directory -Filter ('*-'+$token));if($dirs.Count -ne 1){throw 'Missing or ambiguous inspection result'}
    $summaryPath=Join-Path $dirs[0].FullName 'summary.json';$inventoryPath=Join-Path $dirs[0].FullName 'post-recovery-inventory.json'
    $summary=Read-NikkePinnedJson $summaryPath (Get-NikkeFileDigest $summaryPath).SHA256
    $inventory=Read-NikkePinnedJson $inventoryPath (Get-NikkeFileDigest $inventoryPath).SHA256
    if($summary.RunToken -ne $token -or $summary.TargetSID -ne $sid -or $inventory.TargetSid -ne $sid){throw 'Inspection identity mismatch'}
    if($priorProblem){$summary.Issues+= [pscustomobject]@{Area='PreviousAftercareState';Error=$priorProblem}}
    $boot='';try{$boot=(Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 10 -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')}catch{$summary.Issues += [pscustomobject]@{Area='BootTime';Error=$_.Exception.Message}}
    $plans=@()
    if($BaselineConfigPath){
        try {
            $config=Read-NikkePinnedJson $BaselineConfigPath $BaselineConfigSHA256
            if($config.Schema -ne 1 -or @($config.Checks).Count -gt 5){throw 'At most five pinned program checks per run are supported'}
            foreach($check in $config.Checks){$baseline=Read-NikkePinnedJson $check.BaselinePath $check.BaselineSHA256;$plan=New-NikkeIntegrityPlan $baseline $check.BaselineSHA256 $check.TargetRoot -MaxSeconds 30;$plans+=$plan}
            Save-Json (Join-Path $run 'integrity-plans.json') $plans
        }catch{$summary.Issues += [pscustomobject]@{Area='VendorBaseline';Error=$_.Exception.Message}}
    }
    $previousBoot='';if($null -ne $previous){$previousBoot=$previous.BootId}
    $pending=@();if($null -ne $previous -and $previous.PSObject.Properties['PendingChanges']){$pending=@($previous.PendingChanges)}
    $assessment=New-NikkeAftercareAssessment $summary $inventory $previousSummary $previousInventory $boot $previousBoot $plans $pending
    $assessmentPath=Join-Path $run 'aftercare.json';Save-Json $assessmentPath $assessment
    Save-Json (Join-Path $run 'observation-summary.json') $summary
    $summaryPath=Join-Path $run 'observation-summary.json'
    $changed=($null -eq $previous -or $previous.AlertSignature -ne $assessment.AlertSignature)
    $notice=[ordered]@{Changed=$changed;Requested=[bool]$Notify;Attempted=$false;Error=$null}
    if($changed -and $Notify -and $assessment.Severity -ne 'Observed'){
        try{Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing;$icon=New-Object Windows.Forms.NotifyIcon;try{$icon.Icon=[Drawing.SystemIcons]::Warning;$icon.Visible=$true;$icon.ShowBalloonTip(5000,'NIKKE Recovery Kit',('Review required: '+$assessment.Severity+'. Open STATUS.html in the aftercare folder.'),[Windows.Forms.ToolTipIcon]::Warning);$notice.Attempted=$true;Start-Sleep -Seconds 5}finally{$icon.Dispose()}}catch{$notice.Error=$_.Exception.Message}
    }
    Save-Json (Join-Path $run 'notification.json') $notice
    Write-NikkeAftercareDashboard (Join-Path $StateRoot 'STATUS.html') $assessment $run
    $state=[pscustomobject]@{Schema=1;At=(Get-Date -Format o);RunDirectory=$run;SummaryPath=$summaryPath;SummarySHA256=(Get-NikkeFileDigest $summaryPath).SHA256;InventoryPath=$inventoryPath;InventorySHA256=(Get-NikkeFileDigest $inventoryPath).SHA256;BootId=$boot;AlertSignature=$assessment.AlertSignature;Severity=$assessment.Severity;PendingChanges=$assessment.PendingChanges;WholeHostCleanClaim=$false}
    Save-NikkeAtomicJson $statePath $state
    [pscustomobject]@{Result=$assessment.Severity;Changed=$changed;NewBootObserved=$assessment.NewBootObserved;Report=$assessmentPath;Dashboard=(Join-Path $StateRoot 'STATUS.html');WholeHostCleanClaim=$false}|ConvertTo-Json
}catch{
    if($held -and $initialized -and (Test-Path -LiteralPath $StateRoot -PathType Container)){
        $failure=[pscustomobject]@{At=(Get-Date -Format o);Severity='InspectionFailed';Error=$_.Exception.Message;Location=$_.ScriptStackTrace;WholeHostCleanClaim=$false;LatestSuccessfulStateNotReplaced=$true}
        Save-NikkeAtomicJson (Join-Path $StateRoot 'last-failure.json') $failure
        Write-NikkeAftercareDashboard (Join-Path $StateRoot 'STATUS.html') $failure $StateRoot
    }
    Write-Error $_;exit 1
}finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}

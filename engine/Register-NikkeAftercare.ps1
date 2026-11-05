#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param([ValidateSet('Plan','Install','Status','Remove')][string]$Mode='Plan',[ValidateRange(1,168)][int]$Hours=6,[string]$StateRoot=(Join-Path $env:LOCALAPPDATA 'NikkeRecovery\Aftercare'),[switch]$Notify,[string]$BaselineConfigPath='',[string]$BaselineConfigSHA256='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Test-NikkePackage.ps1');Assert-NikkePackage $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Integrity.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Aftercare.psm1') -DisableNameChecking
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name='NIKKE-Recovery-Aftercare-'+$sid;$entry=Join-Path $PSScriptRoot 'Invoke-NikkeAftercare.ps1'
$StateRoot=Get-CanonicalPath $StateRoot;Assert-NoReparse $StateRoot
if($BaselineConfigPath){$null=Read-NikkePinnedJson $BaselineConfigPath $BaselineConfigSHA256}
$xml=New-NikkeAftercareTaskXml $entry $StateRoot $sid $Hours ([bool]$Notify) $BaselineConfigPath $BaselineConfigSHA256
if($Mode -eq 'Plan'){
    Initialize-NikkeAftercareState $StateRoot $sid;$out=Join-Path $StateRoot ('task-plan-'+[guid]::NewGuid().ToString('N')+'.xml');[IO.File]::WriteAllText($out,$xml,[Text.Encoding]::Unicode)
    [pscustomobject]@{TaskName=$name;Xml=$out;Registered=$false;IntervalHours=$Hours;AtUserLogon=$true;Privilege='CurrentUserLimited';AutomaticRepair=$false}|ConvertTo-Json;exit 0
}
$existing=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object TaskName -eq $name)
if($existing.Count){
    $task=$existing[0];$actions=@($task.Actions)
    if($task.Author -ne 'NIKKE Recovery Kit' -or $task.Principal.UserId -ne $sid -or $actions.Count -ne 1 -or $actions[0].Execute -ine (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -or -not $actions[0].Arguments.Contains('-File "'+$entry+'"')){throw 'Existing task ownership or action mismatch; left untouched'}
}
if($Mode -eq 'Status'){[pscustomobject]@{TaskName=$name;Installed=[bool]$existing.Count;Task=$existing;AutomaticRepair=$false}|ConvertTo-Json -Depth 6;exit 0}
if($Mode -eq 'Remove'){
    if($existing.Count -and $PSCmdlet.ShouldProcess($name,'Remove this tool-owned scheduled check')){Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false -ErrorAction Stop}
    Write-Output 'Task removed or already absent; evidence and network containment retained.';exit 0
}
if($existing.Count){throw 'An aftercare task already exists. Review Status and remove it explicitly before changing its schedule.'}
if($PSCmdlet.ShouldProcess($name,'Install a read-only scheduled check for the current logged-in user')){
    Initialize-NikkeAftercareState $StateRoot $sid
    Register-ScheduledTask -TaskName $name -TaskPath '\' -Xml $xml -ErrorAction Stop|Out-Null
    $check=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
    if($check.Principal.RunLevel -ne 'Limited' -or $check.Principal.UserId -ne $sid){throw 'Registered task properties require review'}
    [pscustomobject]@{TaskName=$name;Installed=$true;AutomaticRepair=$false;Privilege='CurrentUserLimited';StateRoot=$StateRoot}|ConvertTo-Json
}

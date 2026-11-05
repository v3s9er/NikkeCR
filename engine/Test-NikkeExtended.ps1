#requires -Version 5.1
param([string]$OutputRoot=$env:TEMP)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Lua.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.PostRecovery.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.FollowUp.psm1') -Force -DisableNameChecking
$root=Join-Path $OutputRoot ('NikkeExtendedTests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$results=New-Object 'Collections.Generic.List[object]'
function Check([string]$Name,[scriptblock]$Body){try{&$Body;$results.Add([pscustomobject]@{Name=$Name;Passed=$true});Write-Host ('PASS '+$Name)}catch{$results.Add([pscustomobject]@{Name=$Name;Passed=$false;Error=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}}
function Assert($x){if(-not $x){throw 'Assertion failed'}}
$f=Join-Path $root 'insight.bundle';[IO.File]::WriteAllText($f,'ordinary text with a suspicious filename')
Check 'A suspicious Lua filename cannot convict normal text' {Assert ((Get-IncidentLuaVerdict $f).Verdict -eq 'NotDetected')}
$bytes=New-Object byte[] 120000;$bytes[0]=27;$bytes[1]=76;$bytes[2]=74;$bytes[3]=1
[IO.File]::WriteAllBytes($f,$bytes)
Check 'Ordinary LuaJIT header does not identify this malware' {Assert ((Get-IncidentLuaVerdict $f).Verdict -eq 'NotDetected')}
$tab85=[byte[]]@(1,0,85,6,65,3,0,6,66,3,1,6,67,3,2,6,68,3,3)
$tab64=[byte[]]@(1,0,64,6,69,3,0,6,70,3,1,6,71,3,2,6,72,3,3)
$tab85.CopyTo($bytes,200);[IO.File]::WriteAllBytes($f,$bytes)
Check 'One substitution table is insufficient' {Assert ((Get-IncidentLuaVerdict $f).Verdict -eq 'NotDetected')}
$tab64.CopyTo($bytes,400);[IO.File]::WriteAllBytes($f,$bytes)
Check 'Combined structural lead never authorizes automatic deletion' {$r=Get-IncidentLuaVerdict $f;Assert ($r.Verdict -eq 'SuspectedK2f');Assert (-not $r.AutomaticRemoval);Assert (Test-Path -LiteralPath $f)}
Check 'Read-only Lua scan preserves every specimen byte' {$before=(Get-FileHash -LiteralPath $f).Hash;$r=Find-IncidentLuaFiles -Roots @($root);Assert ($r.Findings.Count -eq 1);Assert ((Get-FileHash -LiteralPath $f).Hash -eq $before)}
Check 'Evidence exclusion prevents sample collections becoming active hits' {$r=Find-IncidentLuaFiles -Roots @($root) -ExcludeRoots @($root);Assert ($r.Findings.Count -eq 0);Assert ($r.FilesChecked -eq 0)}
$sub=Join-Path $root 'Deep';New-Item -ItemType Directory -Path $sub | Out-Null
[IO.File]::WriteAllText((Join-Path $sub 'ordinary.txt'),'benign')
Check 'Directory depth limit is reported as incomplete coverage' {$r=Find-IncidentLuaFiles -Roots @($root) -MaxDepth 0;Assert $r.Truncated}
Check 'Elapsed-time budget reports incomplete coverage' {$r=Find-IncidentLuaFiles -Roots @($root) -MaxSeconds 0;Assert $r.Truncated;Assert ($r.Findings.Count -eq 0)}
$link=Join-Path $root 'junction';New-Item -ItemType Junction -Path $link -Target $sub | Out-Null
Check 'Reparse points are reported and not traversed' {$r=Find-IncidentLuaFiles -Roots @($root);Assert (@($r.Errors | Where-Object {$_.Error -match 'Reparse'}).Count -ge 1)}
[IO.Directory]::Delete($link)
$tinyRoot=Join-Path $root 'Official\Launcher\log\tinyget';New-Item -ItemType Directory -Path $tinyRoot -Force | Out-Null
$tiny=Join-Path $tinyRoot 'tinyget.2026-11-01-12-30-00.log';$plain=New-Object byte[] 205135;[IO.File]::WriteAllBytes($tiny,$plain)
Check 'Official tinyget size name and context produce review without deletion' {$before=(Get-FileHash -LiteralPath $tiny).Hash;$v=Get-IncidentLuaVerdict $tiny;Assert ($v.Verdict -eq 'OfficialTinygetReview');Assert (-not $v.AutomaticRemoval);Assert ($v.Bytes -eq 205135);Assert ($v.SHA256 -eq $before.ToLowerInvariant());Assert ((Get-FileHash -LiteralPath $tiny).Hash -eq $before)}
Check 'Official tinyget review is included by bounded discovery' {$v=Find-IncidentLuaFiles -Roots @($tinyRoot);Assert ($v.Findings.Count -eq 1);Assert ($v.Findings[0].Verdict -eq 'OfficialTinygetReview')}
Check 'Matching size outside tinyget context is insufficient' {$p=Join-Path $root 'tinyget.2026-11-01-12-30-00.log';[IO.File]::WriteAllBytes($p,$plain);Assert ((Get-IncidentLuaVerdict $p).Verdict -eq 'NotDetected')}
Check 'Matching size with unrelated filename is insufficient' {$p=Join-Path $tinyRoot 'normal.log';[IO.File]::WriteAllBytes($p,$plain);Assert ((Get-IncidentLuaVerdict $p).Verdict -eq 'NotDetected')}
Check 'Tinyget size boundary is exact' {$p=Join-Path $tinyRoot 'tinyget.2026-11-01-12-30-01.log';[IO.File]::WriteAllBytes($p,(New-Object byte[] 205134));Assert ((Get-IncidentLuaVerdict $p).Verdict -eq 'NotDetected');[IO.File]::WriteAllBytes($p,(New-Object byte[] 205136));Assert ((Get-IncidentLuaVerdict $p).Verdict -eq 'NotDetected')}
Check 'Quoted executable path preserves spaces and strips arguments' {Assert ((Get-ProgramCommandPath '"C:\Program Files\Vendor\app.exe" --example') -eq 'C:\Program Files\Vendor\app.exe')}
Check 'Relative command is unresolved instead of PATH execution' {Assert ($null -eq (Get-ProgramCommandPath 'powershell.exe -Command whatever'))}
Check 'UNC command is unresolved' {Assert ($null -eq (Get-ProgramCommandPath '\\server\share\app.exe'))}
Check 'Alternate profile variables are not expanded to the administrator profile' {Assert ($null -eq (Get-ProgramCommandPath '%APPDATA%\vendor\app.exe' 'C:\Users\DifferentFixtureProfile'))}
Check 'Worker rejects an unsupported SID before launching a process' {$caught=$false;try{Get-PostRecoveryInventoryBounded -TargetSid 'S-1-5-18' -TargetProfile $root -OutputDirectory $root | Out-Null}catch{$caught=$true};Assert $caught}
Check 'Worker file hashing works without PowerShell Get-FileHash autoload' {$p=Join-Path $root 'hash-fixture.txt';[IO.File]::WriteAllBytes($p,[Text.Encoding]::ASCII.GetBytes('abc'));Assert ((Get-InventoryFileHash $p) -eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')}
Check 'Worker refuses to overwrite prior inventory evidence' {$p=Join-Path $root 'inventory-worker.json';[IO.File]::WriteAllText($p,'KEEP');$caught=$false;try{Get-PostRecoveryInventoryBounded -TargetSid 'S-1-5-21-1-2-3-1001' -TargetProfile $root -OutputDirectory $root | Out-Null}catch{$caught=$true};Assert $caught;Assert ([IO.File]::ReadAllText($p) -eq 'KEEP')}
Check 'Coverage counts files skipped by time limits as unexamined' {$links=@([pscustomobject]@{Kind='Service';FilePath='C:\a.exe'},[pscustomobject]@{Kind='Service';FilePath='C:\b.exe'},[pscustomobject]@{Kind='Service';FilePath='C:\a.exe'});$files=@([pscustomobject]@{Path='C:\a.exe';SHA256='fixture';Disposition='InventoryOnly'});$c=Get-InventoryCoverage $links $files;Assert ($c.PendingFileCount -eq 1);Assert ($c.MissingOrUnexaminedFiles -eq 1);Assert ($c.ReferencedFileCount -eq 2);Assert ($c.HashedFileCount -eq 1)}
Check 'Checkpoint retains completed file hashes without claiming completion' {$p=Join-Path $root 'checkpoint.json';Save-InventoryCheckpoint $p @{ReferencedFiles=@();FileInspectionCompleted=$false};Save-InventoryCheckpoint $p @{ReferencedFiles=@(@{Path='C:\fixture.exe';SHA256='fixture'});FileInspectionCompleted=$false};$v=Get-Content -Encoding UTF8 -LiteralPath $p -Raw | ConvertFrom-Json;Assert ($v.ReferencedFiles[0].SHA256 -eq 'fixture');Assert (-not $v.FileInspectionCompleted);Assert (-not(Test-Path -LiteralPath ($p+'.next')))}
Check 'Interrupted checkpoint never overwrites the preceding valid result' {$p=Join-Path $root 'checkpoint-protected.json';Save-InventoryCheckpoint $p @{State='KEEP'};[IO.File]::WriteAllText(($p+'.next'),'INTERRUPTED');$caught=$false;try{Save-InventoryCheckpoint $p @{State='REPLACE'}}catch{$caught=$true};Assert $caught;Assert ((Get-Content -Encoding UTF8 -LiteralPath $p -Raw | ConvertFrom-Json).State -eq 'KEEP')}
$program=[pscustomobject]@{Name='Fixture app';Version='1';Publisher='Fixture vendor';Location='C:\FixtureApp';RegistryPath='FixtureRegistry'}
$launch=[pscustomobject]@{Kind='Service';Source='FixtureService';Name='Fixture';Command='C:\FixtureApp\app.exe';Arguments='';FilePath='C:\FixtureApp\app.exe'}
$inv=[pscustomobject]@{InstalledPrograms=@($program);LaunchRelationships=@($launch);ConfirmedReferences=@();ReferencedFiles=@([pscustomobject]@{Path=$launch.FilePath;SHA256='before';Disposition='InventoryOnly'});BrowserPolicies=@();WorkerCompleted=$true;Errors=@();Coverage=@{}}
Check 'Program association never becomes an integrity or repair verdict' {$r=New-ProgramRecoveryPlan $inv;Assert ($r.Programs[0].RelatedLaunchReferences.Count -eq 1);Assert (-not $r.Programs[0].TrustedBaselineVerified);Assert (-not $r.Programs[0].AutomaticRepair);Assert ($r.Programs[0].Status -eq 'NotIntegrityVerified')}
Check 'Similar path prefix is not assigned to a different program' {$copy=$inv | ConvertTo-Json -Depth 12 | ConvertFrom-Json;$copy.LaunchRelationships[0].FilePath='C:\FixtureApplication\other.exe';$r=New-ProgramRecoveryPlan $copy;Assert ($r.Programs[0].RelatedLaunchReferences.Count -eq 0);Assert ($r.UnassignedLaunchReferences.Count -eq 1)}
Check 'Incident reference prompts component review without automatic repair' {$copy=$inv | ConvertTo-Json -Depth 12 | ConvertFrom-Json;$copy.ConfirmedReferences=@([pscustomobject]@{Path=$launch.FilePath;Reason='Fixture'});$r=New-ProgramRecoveryPlan $copy;Assert ($r.Programs[0].Status -eq 'IncidentReferenceNeedsReview');Assert (-not $r.Programs[0].AutomaticRepair)}
Check 'Changed executable hash is recorded for post-reboot investigation' {$copy=$inv | ConvertTo-Json -Depth 12 | ConvertFrom-Json;$copy.ReferencedFiles[0].SHA256='after';$r=Compare-RecoveryInventories $inv $copy;Assert ($r.Changes.Count -eq 1);Assert ($r.Changes[0].Area -eq 'ReferencedFile');Assert ($r.Changes[0].Change -eq 'Changed')}
Check 'Identical snapshots do not become proof of recovery' {$r=Compare-RecoveryInventories $inv $inv;Assert ($r.Changes.Count -eq 0);Assert (-not $r.WholeHostCleanClaim);Assert (-not $r.TrustedBaselineProvided)}
Check 'A missing later startup row is not claimed as successful removal' {$copy=$inv | ConvertTo-Json -Depth 12 | ConvertFrom-Json;$copy.LaunchRelationships=@();$copy.WorkerCompleted=$false;$r=Compare-RecoveryInventories $inv $copy;Assert ($r.Changes[0].Change -eq 'AbsentFromLaterSnapshot');Assert (-not $r.AfterInventoryCompleted)}
Check 'All shipped PowerShell files parse' {foreach($p in Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object Extension -in '.ps1','.psm1'){$t=$null;$e=$null;[Management.Automation.Language.Parser]::ParseFile($p.FullName,[ref]$t,[ref]$e)|Out-Null;Assert (@($e).Count -eq 0)}}
$failed=@($results|Where-Object {-not $_.Passed})
Save-Json (Join-Path $root 'results.json') @{PowerShell=$PSVersionTable.PSVersion.ToString();Passed=$results.Count-$failed.Count;Failed=$failed.Count;Tests=$results.ToArray();MalwareExecuted=$false;HostSettingsModified=$false}
Write-Host ('Evidence: '+$root)
if($failed.Count){throw 'Extended tests failed'}

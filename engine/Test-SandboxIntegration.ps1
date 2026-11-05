#requires -Version 5.1
# This creates inert indicators in a disposable Windows Sandbox, never on the incident host.
$ErrorActionPreference='Stop'
if ($env:USERNAME -cne 'WDAGUtilityAccount' -or $PSScriptRoot -cne 'C:\NikkeRecoveryTest') {throw 'This integration fixture may run only at the fixed path inside Windows Sandbox.'}
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch '(?i)Virtual Machine') {throw 'Disposable VM model check failed.'}
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -Force -DisableNameChecking
$key='Registry::HKEY_CURRENT_USER\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
$root=Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\PlatformExperienceHelper'
$cache=Join-Path $env:APPDATA 'nikke_launcher\tbs_cache'
if ((Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $cache)) {throw 'Pre-existing data found; refusing to replace anything.'}
$dllDir=Join-Path $root ('a'*64);New-Item -ItemType Directory -Path $dllDir,$cache -Force | Out-Null
$dll=Join-Path $dllDir 'platform_experience_helper.dll'
$bytes=New-Object byte[] 2048;$bytes[0]=0x4d;$bytes[1]=0x5a;[BitConverter]::GetBytes([int]128).CopyTo($bytes,0x3c);$bytes[128]=0x50;$bytes[129]=0x45;[BitConverter]::GetBytes([uint16]0x2000).CopyTo($bytes,150)
[Text.Encoding]::ASCII.GetBytes('analytics.insightjs.com/px/ Debugger.paused Debugger.scriptParsed Runtime.callFunctionOn WinHttpSendRequest').CopyTo($bytes,256)
[IO.File]::WriteAllBytes($dll,$bytes)
[IO.File]::WriteAllText((Join-Path $root 'platform_experience_helper.exe'),'INERT NORMAL HELPER FIXTURE - DO NOT EXECUTE')
[IO.File]::WriteAllText((Join-Path $cache 'fixture.txt'),'INERT CACHE EVIDENCE')
New-Item -Path ($key+'\InprocServer32') -Force | Out-Null
Set-Item -LiteralPath ($key+'\InprocServer32') -Value $dll
$machineKey='Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32'
$machineBefore=$null;if (Test-Path -LiteralPath $machineKey) {$machineBefore=[string](Get-Item -LiteralPath $machineKey).GetValue('')}
& (Join-Path $PSScriptRoot 'Invoke-NikkeRecovery.ps1') -Mode Apply -OutputRoot 'C:\NikkeRecoveryResults'
if ((Test-Path -LiteralPath $dll) -or (Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $cache)) {throw 'Synthetic cleanup did not remove active fixture locations.'}
if ([IO.File]::ReadAllText((Join-Path $root 'platform_experience_helper.exe')) -ne 'INERT NORMAL HELPER FIXTURE - DO NOT EXECUTE') {throw 'Normal helper fixture changed.'}
$machineAfter=$null;if (Test-Path -LiteralPath $machineKey) {$machineAfter=[string](Get-Item -LiteralPath $machineKey).GetValue('')}
if ($machineBefore -cne $machineAfter) {throw 'HKLM COM registration changed.'}
& (Join-Path $PSScriptRoot 'Invoke-NikkeRecovery.ps1') -Mode Plan -OutputRoot 'C:\NikkeRecoveryResults'
$latest=Get-ChildItem -LiteralPath 'C:\NikkeRecoveryResults' -Directory | Sort-Object Name -Descending | Select-Object -First 1
$plan=Get-Content -Encoding UTF8 -Raw -LiteralPath (Join-Path $latest.FullName 'plan.json') | ConvertFrom-Json
if (@($plan).Count -ne 0) {throw 'Second run is not idempotent.'}
[IO.File]::WriteAllText('C:\NikkeRecoveryResults\INTEGRATION-PASS.txt','Synthetic cleanup, normal-helper preservation, HKLM preservation and idempotency passed. No malware was executed.')
Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList 'C:\NikkeRecoveryResults' -WindowStyle Hidden

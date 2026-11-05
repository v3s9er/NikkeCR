#requires -Version 5.1
[CmdletBinding()]param([string]$OutputPath=(Join-Path $env:TEMP 'NikkeRecovery-synthetic-test.wsb'))
$ErrorActionPreference='Stop'
$source=[Security.SecurityElement]::Escape($PSScriptRoot)
$command='powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Copy-Item -LiteralPath C:\NikkeRecoverySource -Destination C:\NikkeRecoveryTest -Recurse; & C:\NikkeRecoveryTest\Test-SandboxIntegration.ps1"'
$escapedCommand=[Security.SecurityElement]::Escape($command)
$xml=@"
<Configuration>
  <Networking>Disable</Networking>
  <vGPU>Disable</vGPU>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders><MappedFolder><HostFolder>$source</HostFolder><SandboxFolder>C:\NikkeRecoverySource</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders>
  <LogonCommand><Command>$escapedCommand</Command></LogonCommand>
</Configuration>
"@
$null=[xml]$xml
if (Test-Path -LiteralPath $OutputPath) {throw 'Output already exists; refusing overwrite.'}
[IO.File]::WriteAllText($OutputPath,$xml,(New-Object Text.UTF8Encoding($false)))
Write-Host ('Created only, not launched: '+$OutputPath)
Write-Host 'Contains inert synthetic fixtures only. No live malware or private host evidence is mapped.'

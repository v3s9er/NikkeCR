#requires -Version 5.1
[CmdletBinding()]param([switch]$Package)
$ErrorActionPreference='Stop';$root=Split-Path $PSScriptRoot -Parent
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path -LiteralPath $compiler)){throw 'The .NET Framework C# compiler is required'}
# PowerShell 5.1 needs a BOM to correctly decode Korean source.
foreach($f in Get-ChildItem -LiteralPath $root -Recurse -File|Where-Object {$_.Extension -in @('.ps1','.psm1','.cs') -and $_.FullName -notmatch '[\\/]\.git[\\/]'}){$t=[IO.File]::ReadAllText($f.FullName,[Text.Encoding]::UTF8);[IO.File]::WriteAllText($f.FullName,$t,(New-Object Text.UTF8Encoding($true)))}
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $root 'NikkeCR.exe')) (Join-Path $root 'src\NikkeCR.cs')
if($LASTEXITCODE -ne 0){throw 'Compilation failed'}
if($Package){Add-Type -AssemblyName System.IO.Compression}
$engine=Join-Path $root 'engine';$rows=@(Get-ChildItem -LiteralPath $engine -File|Where-Object Name -ne 'PACKAGE-SHA256.json'|Sort-Object Name|ForEach-Object {[ordered]@{File=$_.Name;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();Bytes=$_.Length}})
[IO.File]::WriteAllText((Join-Path $engine 'PACKAGE-SHA256.json'),((@{Version='0.3.1-preview';Files=$rows}|ConvertTo-Json -Depth 6)),(New-Object Text.UTF8Encoding($false)))
$files=@(Get-ChildItem -LiteralPath $root -Recurse -File|Where-Object {$_.FullName -notmatch '[\\/]\.git[\\/]|[\\/]dist[\\/]' -and $_.Name -ne 'NikkeCR-SHA256.json'}|Sort-Object FullName|ForEach-Object {[ordered]@{Path=$_.FullName.Substring($root.Length+1).Replace('\','/');SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();Length=$_.Length}})
[IO.File]::WriteAllText((Join-Path $root 'NikkeCR-SHA256.json'),((@{Version='0.4.4-preview';PublisherAuthenticated=$false;Files=$files}|ConvertTo-Json -Depth 6)),(New-Object Text.UTF8Encoding($false)))
if($Package){$dist=Join-Path $root 'dist';New-Item -ItemType Directory -Path $dist -Force|Out-Null;$zip=Join-Path $dist 'NikkeCR-0.4.4-preview-win-x64.zip';if(Test-Path -LiteralPath $zip){Remove-Item -LiteralPath $zip -Force};Add-Type -AssemblyName System.IO.Compression.FileSystem;$archive=[IO.Compression.ZipFile]::Open($zip,[IO.Compression.ZipArchiveMode]::Create);try{foreach($f in @($files)+@(@{Path='NikkeCR-SHA256.json'})){[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,(Join-Path $root $f.Path),('NikkeCR/'+$f.Path),[IO.Compression.CompressionLevel]::Optimal)|Out-Null}}finally{$archive.Dispose()};$hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant();[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'),($hash+'  '+[IO.Path]::GetFileName($zip)+"`n"));Write-Host ('Package SHA256: '+$hash)}
Write-Host 'NikkeCR build complete'

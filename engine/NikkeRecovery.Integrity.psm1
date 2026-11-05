# Compare pinned vendor ZIP contents; never run an installer or a recovered file.
Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
Add-Type -AssemblyName System.IO.Compression
function Get-NikkeStreamDigest($Stream,[long]$MaxBytes=134217728) {
    $sha=[Security.Cryptography.SHA256]::Create();$buffer=New-Object byte[] 65536;[long]$total=0
    try {while(($n=$Stream.Read($buffer,0,$buffer.Length)) -gt 0){$total+=$n;if($total -gt $MaxBytes){throw 'Content exceeds inspection limit'};[void]$sha.TransformBlock($buffer,0,$n,$buffer,0)};[void]$sha.TransformFinalBlock($buffer,0,0);return [pscustomobject]@{SHA256=([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant();Bytes=$total}}finally{$sha.Dispose()}
}
function Get-NikkeFileDigest([string]$Path,[long]$MaxBytes=2147483648) {
    Assert-NoReparse $Path
    $s=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {Get-NikkeStreamDigest $s $MaxBytes}finally{$s.Dispose()}
}
function Save-NikkeAtomicJson([string]$Path,$Value) {
    Assert-NoReparse $Path
    $temp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    Save-Json $temp $Value
    if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temp,$Path,[NullString]::Value)}else{[IO.File]::Move($temp,$Path)}
}
function Read-NikkePinnedJson([string]$Path,[string]$ExpectedSHA256) {
    if($ExpectedSHA256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'An independently retained SHA-256 is required'}
    Assert-NoReparse $Path
    $s=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {if($s.Length -gt 32MB){throw 'JSON exceeds 32 MiB'};$digest=Get-NikkeStreamDigest $s 32MB;if($digest.SHA256 -ine $ExpectedSHA256){throw 'Pinned JSON hash mismatch'};$s.Position=0;$reader=New-Object IO.StreamReader($s,[Text.Encoding]::UTF8,$true);try{$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}}finally{$s.Dispose()}
}
function ConvertTo-NikkeRelativePath([string]$Name) {
    $n=$Name.Replace('/','\')
    if([string]::IsNullOrWhiteSpace($n) -or $n.StartsWith('\') -or $n -match '[:*?"<>|\x00-\x1f]'){throw 'Unsafe archive or relative path'}
    foreach($part in $n.Split('\')){if(-not $part -or $part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)'){throw 'Ambiguous Windows path refused'}}
    return $n
}
function Test-NikkeRepairableExtension([string]$Path) {return [IO.Path]::GetExtension($Path).ToLowerInvariant() -in @('.exe','.dll','.ocx','.pyd','.node')}
function Assert-NikkeProgramRoot([string]$Root) {
    $p=Get-CanonicalPath $Root;Assert-NoReparse $p
    if($p.Length -le 3 -or -not(Test-Path -LiteralPath $p -PathType Container)){throw 'Select an existing application-specific directory'}
    foreach($reserved in @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData,$env:USERPROFILE,$env:LOCALAPPDATA,$env:APPDATA,$PSScriptRoot)){
        if($reserved -and $p -ieq (Get-CanonicalPath $reserved)){throw 'Broad/system/tool root cannot be a repair target'}
    }
    if(Test-PathWithin $p $env:SystemRoot){throw 'Windows components require supported Windows servicing, not file replacement'}
    if($p -match '(?i)\\WindowsApps(?:\\|$)'){throw 'MSIX-managed directories require vendor servicing'}
    return $p
}
function Get-NikkeArchiveFiles([string]$PackagePath,[string]$ExpectedSHA256,[string]$ArchivePrefix='') {
    if($ExpectedSHA256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Pin the vendor package SHA-256 first'}
    $prefix='';if($ArchivePrefix){$prefix=(ConvertTo-NikkeRelativePath $ArchivePrefix.TrimEnd('\','/'))+'\'}
    Assert-NoReparse $PackagePath
    $stream=[IO.File]::Open($PackagePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $digest=Get-NikkeStreamDigest $stream 2GB;if($digest.SHA256 -ine $ExpectedSHA256){throw 'Vendor package hash mismatch'};$stream.Position=0
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        try {
            if($zip.Entries.Count -gt 20000){throw 'Archive has too many entries'}
            $seen=@{};$rows=New-Object 'Collections.Generic.List[object]';[long]$total=0
            foreach($entry in $zip.Entries){
                $raw=$entry.FullName.TrimEnd('/','\');if(-not $raw){continue};$path=ConvertTo-NikkeRelativePath $raw
                if((($entry.ExternalAttributes -shr 16) -band 61440) -eq 40960){throw 'Archive symlinks are refused'}
                if($seen.ContainsKey($path)){throw 'Duplicate case-insensitive archive path'};$seen[$path]=$true
                if($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')){continue}
                $total+=$entry.Length;if($entry.Length -gt 128MB -or $total -gt 1GB){throw 'Uncompressed archive exceeds limits'}
                if($prefix -and -not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){continue}
                $relative=$path;if($prefix){$relative=$path.Substring($prefix.Length)};$relative=ConvertTo-NikkeRelativePath $relative
                $s=$entry.Open();try{$hash=Get-NikkeStreamDigest $s 128MB}finally{$s.Dispose()}
                if($hash.Bytes -ne $entry.Length){throw 'Archive entry length mismatch'}
                $rows.Add([pscustomobject]@{RelativePath=$relative;ArchiveEntry=$entry.FullName;SHA256=$hash.SHA256;Bytes=$hash.Bytes;BinaryRepairEligible=(Test-NikkeRepairableExtension $relative)})
            }
            if(-not $rows.Count){throw 'No package files in selected prefix'}
            return $rows.ToArray()
        }finally{$zip.Dispose()}
    }finally{$stream.Dispose()}
}
function New-NikkeVendorBaseline([string]$PackagePath,[string]$ExpectedSHA256,[string]$ProgramName,[string]$ProgramVersion,[string]$SourceUri,[string]$ArchivePrefix='') {
    $uri=[Uri]$SourceUri;if($uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo){throw 'Record the official HTTPS source without credentials'}
    if(-not $ProgramName -or -not $ProgramVersion){throw 'Program name and exact version are required'}
    $files=@(Get-NikkeArchiveFiles $PackagePath $ExpectedSHA256 $ArchivePrefix)
    return [pscustomobject]@{Schema=1;Kind='NikkeVendorBaseline';At=(Get-Date -Format o);ProgramName=$ProgramName;ProgramVersion=$ProgramVersion;SourceUri=$SourceUri;PackageSHA256=$ExpectedSHA256.ToLowerInvariant();ArchivePrefix=$ArchivePrefix;Files=$files;Trust='OperatorPinnedArchive';PublisherAuthenticityVerified=$false;Limitations=@('The operator must obtain the package and hash from a trusted vendor channel. A supplied hash and HTTPS URL alone do not authenticate the publisher.','This baseline describes one selected package version and layout, not every installed version. No installer or package file was executed.')}
}
function Assert-NikkeBaseline($Baseline) {
    if($Baseline.Schema -ne 1 -or $Baseline.Kind -ne 'NikkeVendorBaseline' -or $Baseline.PackageSHA256 -notmatch '^[a-f0-9]{64}$' -or -not @($Baseline.Files).Count -or @($Baseline.Files).Count -gt 20000){throw 'Unsupported baseline schema'}
    $seen=@{}
    foreach($f in $Baseline.Files){$p=ConvertTo-NikkeRelativePath $f.RelativePath;if($seen.ContainsKey($p) -or $f.SHA256 -notmatch '^[a-f0-9]{64}$' -or $f.Bytes -lt 0 -or $f.Bytes -gt 128MB){throw 'Invalid baseline entry'};$seen[$p]=$true}
}
function New-NikkeIntegrityPlan($Baseline,[string]$BaselineSHA256,[string]$TargetRoot,[int]$MaxFiles=20000,[int]$MaxSeconds=120) {
    Assert-NikkeBaseline $Baseline;$root=Assert-NikkeProgramRoot $TargetRoot
    $rows=New-Object 'Collections.Generic.List[object]';$errors=New-Object 'Collections.Generic.List[object]';$known=@{};$clock=[Diagnostics.Stopwatch]::StartNew();$count=0;$complete=$true
    foreach($f in $Baseline.Files){
        $relative=ConvertTo-NikkeRelativePath $f.RelativePath;$known[$relative]=$true
        $r=[ordered]@{RelativePath=$relative;ExpectedSHA256=$f.SHA256;CurrentSHA256=$null;ExpectedBytes=$f.Bytes;Status='Unexamined';RepairEligible=$false;Reason=$null}
        if($count -ge $MaxFiles -or $clock.Elapsed.TotalSeconds -ge $MaxSeconds){$complete=$false;$r.Reason='Inspection budget exceeded';$rows.Add([pscustomobject]$r);continue};$count++
        try {
            $path=Join-Path $root $relative;Assert-NoReparse $path
            if(-not(Test-Path -LiteralPath $path)){$r.Status='Missing'}
            else{$h=Get-NikkeFileDigest $path 128MB;$r.CurrentSHA256=$h.SHA256;$r.Status='Mismatch';if($h.SHA256 -eq $f.SHA256){$r.Status='Match'}}
            $r.RepairEligible=($r.Status -in @('Missing','Mismatch') -and (Test-NikkeRepairableExtension $relative))
        }catch{$r.Status='Unreadable';$r.Reason=$_.Exception.Message;$complete=$false}
        $rows.Add([pscustomobject]$r)
    }
    $queue=New-Object 'Collections.Generic.Queue[string]';$queue.Enqueue($root);$unexpected=New-Object 'Collections.Generic.List[object]';$visited=0
    while($queue.Count){
        if($visited -ge $MaxFiles -or $clock.Elapsed.TotalSeconds -ge $MaxSeconds){$complete=$false;break}
        $dir=$queue.Dequeue()
        try {
            Assert-NoReparse $dir
            foreach($f in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)){
                $visited++;if($visited -gt $MaxFiles -or $clock.Elapsed.TotalSeconds -ge $MaxSeconds){$complete=$false;break}
                if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$complete=$false;$errors.Add([pscustomobject]@{Path=$f.FullName;Error='Reparse point skipped'});continue}
                if($f.PSIsContainer){$queue.Enqueue($f.FullName);continue}
                $rel=$f.FullName.Substring($root.Length+1)
                if(-not $known.ContainsKey($rel) -and (Test-NikkeRepairableExtension $rel)){$unexpected.Add([pscustomobject]@{RelativePath=$rel;Status='UnlistedBinary';AutomaticRemoval=$false})}
            }
        }catch{$complete=$false;$errors.Add([pscustomobject]@{Path=$dir;Error=$_.Exception.Message})}
    }
    return [pscustomobject]@{Schema=1;Kind='NikkeIntegrityPlan';At=(Get-Date -Format o);ProgramName=$Baseline.ProgramName;ProgramVersion=$Baseline.ProgramVersion;BaselineSHA256=$BaselineSHA256;PackageSHA256=$Baseline.PackageSHA256;TargetRoot=$root;Files=$rows.ToArray();UnlistedBinaries=$unexpected.ToArray();Errors=$errors.ToArray();CoverageComplete=$complete;WholeHostCleanClaim=$false;AutomaticRepair=$false;Interpretation='Differences can be legitimate updates or configuration changes. Review the version and selected files before explicit repair.'}
}
function Invoke-NikkePinnedRepair($Plan,$Baseline,[string]$PackagePath,[string[]]$RelativePath,[string]$EvidenceRoot) {
    Assert-NikkeBaseline $Baseline
    if($Plan.Schema -ne 1 -or $Plan.Kind -ne 'NikkeIntegrityPlan' -or $Plan.PackageSHA256 -ne $Baseline.PackageSHA256){throw 'Repair plan does not match baseline'}
    $root=Assert-NikkeProgramRoot $Plan.TargetRoot;$evidence=Get-CanonicalPath $EvidenceRoot
    if($evidence -ieq $root -or (Test-PathWithin $evidence $root) -or (Test-PathWithin $root $evidence)){throw 'Evidence and application trees must be separate'}
    if([IO.Path]::GetPathRoot($evidence) -ine [IO.Path]::GetPathRoot($root)){throw 'Repair evidence must be on the same volume for atomic backup'}
    $selected=@($RelativePath|ForEach-Object{ConvertTo-NikkeRelativePath $_}|Sort-Object -Unique);if(-not $selected.Count){throw 'Select reviewed files explicitly'}
    $packageFiles=@(Get-NikkeArchiveFiles $PackagePath $Baseline.PackageSHA256 $Baseline.ArchivePrefix)
    if($packageFiles.Count -ne @($Baseline.Files).Count){throw 'Archive and baseline disagree'}
    foreach($f in $Baseline.Files){$actual=@($packageFiles|Where-Object RelativePath -ceq $f.RelativePath);if($actual.Count -ne 1 -or $actual[0].SHA256 -ne $f.SHA256 -or $actual[0].ArchiveEntry -cne $f.ArchiveEntry -or $actual[0].Bytes -ne $f.Bytes){throw 'Archive and baseline entry disagree'}}
    foreach($rel in $selected){$row=@($Plan.Files|Where-Object RelativePath -ceq $rel);$bf=@($Baseline.Files|Where-Object RelativePath -ceq $rel);if($row.Count -ne 1 -or $bf.Count -ne 1 -or -not(Test-NikkeRepairableExtension $rel) -or $row[0].Status -notin @('Missing','Mismatch') -or $row[0].ExpectedSHA256 -ne $bf[0].SHA256){throw 'Selected file is not eligible for binary repair'}}
    foreach($p in @(Get-Process)){try{$path=$p.Path}catch{continue};if($path -and (Test-PathWithin $path $root)){throw 'Close applications running from the selected directory before repair'}}
    $run=Join-Path $evidence ('repair-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
    New-ProtectedDirectory $run ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $outcomes=New-Object 'Collections.Generic.List[object]';$stream=[IO.File]::Open($PackagePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $hash=Get-NikkeStreamDigest $stream 2GB;if($hash.SHA256 -ne $Baseline.PackageSHA256){throw 'Package changed before repair'};$stream.Position=0
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        try {foreach($rel in $selected){
            $row=@($Plan.Files|Where-Object RelativePath -ceq $rel)[0];$bf=@($Baseline.Files|Where-Object RelativePath -ceq $rel)[0]
            $target=Join-Path $root $rel;$id=[guid]::NewGuid().ToString('N');$saved=Join-Path $run ($id+'.original.quarantined');$atomicBackup=Join-Path $run ($id+'.atomic-original.quarantined');$staged=$null
            $r=[ordered]@{RelativePath=$rel;Status='Started';OriginalSHA256=$row.CurrentSHA256;ExpectedSHA256=$bf.SHA256;Preserved=$null;AtomicBackup=$null;PlannedPreservation=$saved;PlannedAtomicBackup=$atomicBackup;Error=$null}
            Save-NikkeAtomicJson (Join-Path $run 'repair-results.json') ([pscustomobject]@{At=(Get-Date -Format o);Program=$Baseline.ProgramName;TargetRoot=$root;Outcomes=@($outcomes.ToArray())+@([pscustomobject]$r);WholeHostCleanClaim=$false;AutomaticRollback=$false})
            try {
                Assert-NoReparse $target
                if($row.Status -eq 'Missing'){if(Test-Path -LiteralPath $target){throw 'Missing file appeared after planning'}}
                else{$h=Get-NikkeFileDigest $target 128MB;if($h.SHA256 -ne $row.CurrentSHA256){throw 'Target changed after planning'};[void](Copy-VerifiedEvidence $target $saved $row.CurrentSHA256);$r.Preserved=$saved}
                $parent=[IO.Path]::GetDirectoryName($target);Assert-NoReparse $parent;[IO.Directory]::CreateDirectory($parent)|Out-Null;Assert-NoReparse $parent
                $staged=Join-Path $parent ('.nikke-stage-'+$id+'.tmp');$entry=$zip.GetEntry($bf.ArchiveEntry);if($null -eq $entry){throw 'Pinned archive entry missing'}
                $inputStream=$entry.Open();$outputStream=[IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try{$inputStream.CopyTo($outputStream);$outputStream.Flush()}finally{$outputStream.Dispose();$inputStream.Dispose()}
                if((Get-NikkeFileDigest $staged 128MB).SHA256 -ne $bf.SHA256){throw 'Staged replacement hash mismatch'}
                Assert-NoReparse $target
                if($row.Status -eq 'Missing'){[IO.File]::Move($staged,$target)}
                else{if((Get-NikkeFileDigest $target 128MB).SHA256 -ne $row.CurrentSHA256){throw 'Target changed before replacement'};[IO.File]::Replace($staged,$target,$atomicBackup);$r.AtomicBackup=$atomicBackup;if((Get-NikkeFileDigest $atomicBackup 128MB).SHA256 -ne $row.CurrentSHA256){throw 'Concurrent target change detected; both backups retained; manual review required'}}
                if((Get-NikkeFileDigest $target 128MB).SHA256 -ne $bf.SHA256){throw 'Post-repair content mismatch'};$r.Status='ReplacedAndVerified'
            }catch{$r.Status='Failed';$r.Error=$_.Exception.Message}
            $outcomes.Add([pscustomobject]$r);Save-NikkeAtomicJson (Join-Path $run 'repair-results.json') ([pscustomobject]@{At=(Get-Date -Format o);Program=$Baseline.ProgramName;TargetRoot=$root;Outcomes=$outcomes.ToArray();WholeHostCleanClaim=$false;AutomaticRollback=$false})
            if($r.Status -eq 'Failed'){break}
        }}finally{$zip.Dispose()}
    }finally{$stream.Dispose()}
    return [pscustomobject]@{EvidenceDirectory=$run;Outcomes=$outcomes.ToArray();Failed=@($outcomes|Where-Object Status -eq 'Failed').Count;Selected=$selected.Count;Completed=@($outcomes|Where-Object Status -eq 'ReplacedAndVerified').Count;WholeHostCleanClaim=$false;RestartAndRecheckRequired=$true}
}
Export-ModuleMember -Function Get-NikkeFileDigest,Save-NikkeAtomicJson,Read-NikkePinnedJson,ConvertTo-NikkeRelativePath,New-NikkeVendorBaseline,New-NikkeIntegrityPlan,Invoke-NikkePinnedRepair

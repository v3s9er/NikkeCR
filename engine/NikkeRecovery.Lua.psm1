# Static LuaJIT inspection. No interpreter, native loading, or network access.
Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'NikkeRecovery.Core.psm1') -DisableNameChecking
function Get-IncidentLuaVerdict([string]$Path) {
    $r=[ordered]@{Path=$Path;SHA256=$null;Bytes=0;Verdict='NotDetected';Reason='No known Lua indicator';AutomaticRemoval=$false}
    try {
        Assert-NoReparse $Path
        $f=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($f.PSIsContainer -or $f.Length -gt 16MB) {throw 'Lua candidate exceeds the 16 MiB inspection limit.'}
        $r.Bytes=$f.Length
        # Official manual IOC: size, basename and log/tinyget context are a review lead,
        # never proof that arbitrary content is malicious or permission to delete it.
        $tinyget=($f.Length -eq 205135 -and $f.Name -match '^tinyget\.[0-9][0-9Tt_.-]*\.log$' -and $f.Directory.Name -ieq 'tinyget' -and $f.Directory.Parent.Name -ieq 'log')
        if ($tinyget) {
            $r.Verdict='OfficialTinygetReview';$r.Reason='Official manual size/name/path lead; content and execution remain unconfirmed'
            $h=[Security.Cryptography.SHA256]::Create()
            try {$r.SHA256=([BitConverter]::ToString($h.ComputeHash([IO.File]::ReadAllBytes($f.FullName)))).Replace('-','').ToLowerInvariant()} finally {$h.Dispose()}
        }
        if ($f.Length -lt 4) {return [pscustomobject]$r}
        $stream=[IO.File]::Open($f.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try {$header=New-Object byte[] 4;$n=$stream.Read($header,0,4)} finally {$stream.Dispose()}
        if ($n -ne 4 -or $header[0] -ne 27 -or $header[1] -ne 76 -or $header[2] -ne 74) {return [pscustomobject]$r}
        $data=[IO.File]::ReadAllBytes($f.FullName);$r.Bytes=$data.Length
        $h=[Security.Cryptography.SHA256]::Create()
        try {$r.SHA256=([BitConverter]::ToString($h.ComputeHash($data))).Replace('-','').ToLowerInvariant()} finally {$h.Dispose()}
        # Two constant-pool substitution-table shapes observed in the analyzed specimen.
        # This is an uncalibrated family lead, never authorization to delete arbitrary Lua.
        $text=[Text.Encoding]::GetEncoding(28591).GetString($data)
        $options=[Text.RegularExpressions.RegexOptions]::Singleline
        $a=[regex]::IsMatch($text,'\x01\x00\x55(?:\x06.\x03.){4}',$options)
        $b=[regex]::IsMatch($text,'\x01\x00\x40(?:\x06.\x03.){4}',$options)
        if ($data[3] -eq 1 -and $data.Length -gt 100KB -and $a -and $b) {$r.Verdict='SuspectedK2f';$r.Reason='LuaJIT v1 and both substitution-table shapes; manual analysis required'}
    } catch {$r.Verdict='Unreadable';$r.Reason=$_.Exception.Message}
    return [pscustomobject]$r
}
function Find-IncidentLuaFiles([string[]]$Roots,[string[]]$ExcludeRoots=@(),[int]$MaxFiles=10000,[int]$MaxDepth=8,[int]$MaxSeconds=60) {
    $hits=New-Object 'Collections.Generic.List[object]';$errors=New-Object 'Collections.Generic.List[object]'
    $seen=@{};$queue=New-Object 'Collections.Generic.Queue[object]';$checked=0;$visited=0;$large=0;$truncated=$false;$clock=[Diagnostics.Stopwatch]::StartNew()
    $excluded=@($ExcludeRoots | ForEach-Object {Get-CanonicalPath $_})
    foreach ($root in @($Roots | Sort-Object -Unique)) {
        try {if(Test-Path -LiteralPath $root){$p=Get-CanonicalPath $root;Assert-NoReparse $p;$queue.Enqueue([pscustomobject]@{Path=$p;Depth=0})}}
        catch {$errors.Add([pscustomobject]@{Path=$root;Error=$_.Exception.Message})}
    }
    while($queue.Count) {
        if($clock.Elapsed.TotalSeconds -gt $MaxSeconds){$truncated=$true;break}
        $item=$queue.Dequeue();$key=$item.Path.ToLowerInvariant();if($seen.ContainsKey($key)){continue};$seen[$key]=$true
        if(@($excluded | Where-Object {$item.Path -ieq $_ -or (Test-PathWithin $item.Path $_)}).Count){continue}
        $visited++;if($visited -gt 5000){$truncated=$true;break}
        try {
            Assert-NoReparse $item.Path
            foreach($f in @(Get-ChildItem -LiteralPath $item.Path -Force -ErrorAction Stop)) {
                if(@($excluded | Where-Object {$f.FullName -ieq $_ -or (Test-PathWithin $f.FullName $_)}).Count){continue}
                if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$errors.Add([pscustomobject]@{Path=$f.FullName;Error='Reparse point skipped'});continue}
                if($f.PSIsContainer){if($item.Depth -lt $MaxDepth){$queue.Enqueue([pscustomobject]@{Path=$f.FullName;Depth=$item.Depth+1})}else{$truncated=$true};continue}
                if($checked -ge $MaxFiles -or $clock.Elapsed.TotalSeconds -gt $MaxSeconds){$truncated=$true;break}
                $checked++;if($f.Length -gt 16MB){$large++;continue}
                $v=Get-IncidentLuaVerdict $f.FullName
                if($v.Verdict -eq 'Unreadable'){$errors.Add([pscustomobject]@{Path=$f.FullName;Error=$v.Reason})}
                elseif($v.Verdict -ne 'NotDetected'){$hits.Add($v)}
            }
        }catch{$errors.Add([pscustomobject]@{Path=$item.Path;Error=$_.Exception.Message})}
        if($checked -ge $MaxFiles){if($queue.Count){$truncated=$true};break}
    }
    return [pscustomobject]@{Findings=$hits.ToArray();Errors=$errors.ToArray();FilesChecked=$checked;DirectoriesVisited=$visited;FilesOverSizeLimit=$large;Truncated=$truncated;MaxDepth=$MaxDepth;MaxFiles=$MaxFiles;MaxSeconds=$MaxSeconds;ElapsedSeconds=$clock.Elapsed.TotalSeconds;Roots=$Roots;ExcludedRoots=$excluded;Scope='Bounded selected launcher logs/cache and user temp; not all files';MalwareExecuted=$false}
}
Export-ModuleMember -Function Get-IncidentLuaVerdict,Find-IncidentLuaFiles

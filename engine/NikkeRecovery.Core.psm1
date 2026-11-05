# Read-only identification and narrowly scoped evidence-preserving helpers.
Set-StrictMode -Version 2
$script:KnownDllHashes = @('10e722777685e290e8fd5370d4c5cd1a40d0d7e91b93af0156faefe18467a3f1')
$script:Clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'

function Get-CanonicalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '["\r\n]' -or $Path.IndexOf([char]0) -ge 0) { throw 'Only absolute local Windows paths without alternate streams or control/quote characters are supported.' }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}
function Test-PathWithin([string]$Path,[string]$Root) {
    $p=Get-CanonicalPath $Path; $r=Get-CanonicalPath $Root
    return $p.StartsWith($r+'\',[StringComparison]::OrdinalIgnoreCase)
}
function Get-KnownLauncherExecutables([string]$Root) {
    foreach ($name in @('nikke_launcher.exe','nikke_launcher_google.exe')) {
        $path=Join-Path $Root $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {Write-Output $path}
    }
}
function Get-RecoveryExitCode([object[]]$Outcomes,[bool]$WhatIf=$false) {
    if (@($Outcomes | Where-Object {$_.Status -eq 'Failed'}).Count) {return 2}
    if (-not $WhatIf -and @($Outcomes | Where-Object {$_.Status -eq 'NotApplied'}).Count) {return 2}
    return 0
}
function Get-RecoveryActionField($Object,[string]$Name) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) {return $Object.$Name}
    return $null
}
function Test-ApprovedActionMatch($Current,$Reviewed) {
    if ($null -eq $Current -or $null -eq $Reviewed) {return $false}
    $kind=[string](Get-RecoveryActionField $Current 'Kind')
    $target=[string](Get-RecoveryActionField $Current 'Target')
    if (-not $kind -or -not $target -or $kind -cne [string](Get-RecoveryActionField $Reviewed 'Kind') -or $target -cne [string](Get-RecoveryActionField $Reviewed 'Target')) {return $false}
    $now=Get-RecoveryActionField $Current 'Extra'
    $old=Get-RecoveryActionField $Reviewed 'Extra'
    switch ($kind) {
        'QuarantineDll' {
            $hash=[string](Get-RecoveryActionField $now 'SHA256')
            return ($hash -match '^[a-fA-F0-9]{64}$' -and $hash -ieq [string](Get-RecoveryActionField $old 'SHA256') -and [string](Get-RecoveryActionField $now 'Verdict') -ceq [string](Get-RecoveryActionField $old 'Verdict'))
        }
        'RemoveUserOverride' {
            $disposition=[string](Get-RecoveryActionField $now 'Disposition')
            return ([bool](Get-RecoveryActionField $now 'Exists') -and [bool](Get-RecoveryActionField $old 'Exists') -and -not [bool](Get-RecoveryActionField $now 'UnexpectedSubkeys') -and -not [bool](Get-RecoveryActionField $old 'UnexpectedSubkeys') -and $disposition -in @('MatchedIncidentOverride','EmptyIncidentOverride') -and $disposition -ceq [string](Get-RecoveryActionField $old 'Disposition') -and [string](Get-RecoveryActionField $now 'DefaultValue') -ceq [string](Get-RecoveryActionField $old 'DefaultValue'))
        }
        'BlockLauncher' {return ([string]$now -ceq [string]$old -and [string]$now -in @('Outbound','Inbound'))}
        {$_ -in @('BlockC2','BlockDomains','IsolateCache')} {return $true}
        default {return $false}
    }
}
function Get-ElevationFailureCode([Exception]$Exception) {
    $current=$Exception
    while ($null -ne $current) {
        if ($current.PSObject.Properties['NativeErrorCode'] -and $current.NativeErrorCode -eq 1223) {return 1223}
        $current=$current.InnerException
    }
    return 1
}
function Assert-NoReparse([string]$Path) {
    $p=Get-CanonicalPath $Path
    while ($p) {
        $item=$null
        try {$item=Get-Item -LiteralPath $p -Force -ErrorAction Stop} catch [System.Management.Automation.ItemNotFoundException] {}
        if ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Reparse point refused: '+$p) }
        }
        $parent=[IO.Directory]::GetParent($p)
        if ($null -eq $parent) { break }; $p=$parent.FullName
    }
}
function Get-TreeManifest([string]$Path) {
    Assert-NoReparse $Path
    $root=Get-CanonicalPath $Path; $queue=New-Object 'Collections.Generic.Queue[string]'; $queue.Enqueue($root)
    $rows=New-Object 'Collections.Generic.List[object]'
    while ($queue.Count) {
        $dir=$queue.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Reparse point in evidence tree: '+$item.FullName) }
            if (-not (Test-PathWithin $item.FullName $root)) { throw 'Tree escaped allowed root.' }
            if ($item.PSIsContainer) { $queue.Enqueue($item.FullName) }
            else { $rows.Add([pscustomobject]@{RelativePath=$item.FullName.Substring($root.Length+1);Length=$item.Length;SHA256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}) }
        }
    }
    return $rows.ToArray()
}
function New-ProtectedDirectory([string]$Path,[string]$OwnerSid) {
    Assert-NoReparse $Path
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -ErrorAction Stop -WhatIf:$false | Out-Null }
    # Change only the DACL of the existing directory. A fresh security descriptor
    # can request SACL privileges when Set-Acl is repeated by a limited user.
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $expectedSids=@($OwnerSid,'S-1-5-18','S-1-5-32-544'|Select-Object -Unique)
    $currentRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $invalid=@($currentRules|Where-Object {$_.IdentityReference.Value -notin $expectedSids -or $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $_.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or $_.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or $_.IsInherited})
    if($acl.AreAccessRulesProtected -and -not $invalid.Count -and $currentRules.Count -eq $expectedSids.Count -and @($currentRules.IdentityReference.Value|Sort-Object -Unique).Count -eq $expectedSids.Count){return}
    $acl.SetAccessRuleProtection($true,$false)
    foreach($existingRule in @($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))){[void]$acl.RemoveAccessRuleSpecific($existingRule)}
    foreach ($sid in @($OwnerSid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop -WhatIf:$false
}
function Save-Json([string]$Path,$Value) {
    $text=ConvertTo-Json -InputObject $Value -Depth 14
    [IO.File]::WriteAllText($Path,$text,(New-Object Text.UTF8Encoding($false)))
}
function Get-IncidentDllVerdict([string]$Path,[string]$ProfileRoot) {
    $result=[ordered]@{Path=$Path;SHA256=$null;Bytes=0;Verdict='Review';Reason='Unverified';Markers=@();IsPeDll=$false;LocationMatched=$false}
    try {
        Assert-NoReparse $Path
        if (-not (Test-PathWithin $Path $ProfileRoot)) { throw 'Candidate outside selected profile.' }
        $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -gt 16MB -or $file.Length -lt 64) { throw 'Candidate size/type outside bounded DLL check.' }
        $result['CreationTimeUtc']=$file.CreationTimeUtc.ToString('o');$result['LastWriteTimeUtc']=$file.LastWriteTimeUtc.ToString('o');$result['Attributes']=[string]$file.Attributes
        $bytes=[IO.File]::ReadAllBytes($file.FullName); $result.Bytes=$bytes.Length
        $h=[Security.Cryptography.SHA256]::Create()
        try {$result.SHA256=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()} finally {$h.Dispose()}
        $result.LocationMatched=($file.FullName -match '(?i)\\Google\\Chrome\\User Data\\PlatformExperienceHelper\\[a-f0-9]{64}\\platform_experience_helper\.dll(?:\.disabled[^\\]*)?$')
        $offset=[BitConverter]::ToInt32($bytes,0x3c)
        if ($bytes[0] -eq 0x4d -and $bytes[1] -eq 0x5a -and $offset -ge 64 -and $offset -le ($bytes.Length-24)) {
            $result.IsPeDll=($bytes[$offset] -eq 0x50 -and $bytes[$offset+1] -eq 0x45 -and $bytes[$offset+2] -eq 0 -and $bytes[$offset+3] -eq 0 -and ([BitConverter]::ToUInt16($bytes,$offset+22) -band 0x2000) -ne 0)
        }
        $ascii=[Text.Encoding]::ASCII.GetString($bytes)
        foreach ($marker in @('analytics.insightjs.com/px/','Debugger.paused','Debugger.scriptParsed','Runtime.callFunctionOn','WinHttpSendRequest')) {
            if ($ascii.Contains($marker)) { $result.Markers+= $marker }
        }
        if ($result.SHA256 -in $script:KnownDllHashes) {$result.Verdict='Confirmed';$result.Reason='Previously analyzed exact SHA256'}
        elseif ($result.IsPeDll -and $result.LocationMatched -and $result.Markers.Count -eq 5) {$result.Verdict='StrongMatch';$result.Reason='PE DLL + incident directory shape + all five independent behavior markers; variant heuristic, not a full binary equivalence proof'}
        else {$result.Reason='Filename/location alone is insufficient; retained for review'}
    } catch {$result.Reason=$_.Exception.Message}
    return [pscustomobject]$result
}
function Get-RegistryDisposition([string]$Key,[bool]$Exists,[string]$DefaultValue,[object[]]$Candidates,[bool]$HasUnexpectedSubkeys=$false) {
    if (-not $Exists) {return 'Absent'}
    if ($Key -notmatch ('^Registry::HKEY_USERS\\S-1-5-21-[0-9-]+\\Software\\Classes\\(?:WOW6432Node\\)?CLSID\\'+[regex]::Escape($script:Clsid)+'$')) {return 'Review'}
    if ($HasUnexpectedSubkeys) {return 'Review'}
    if ([string]::IsNullOrWhiteSpace($DefaultValue)) {return 'EmptyIncidentOverride'}
    $value=$DefaultValue.Trim().Trim('"')
    foreach ($candidate in $Candidates) {
        if ($candidate.Verdict -in @('Confirmed','StrongMatch') -and $value -ieq $candidate.Path) {return 'MatchedIncidentOverride'}
    }
    return 'Review'
}
function Test-HostsBlocked([string]$Text,[string]$Domain) {
    foreach ($line in ($Text -split '\r?\n')) {
        $parts=@(($line -split '#',2)[0].Trim() -split '\s+' | Where-Object {$_})
        if ($parts.Count -ge 2 -and $parts[0] -in @('0.0.0.0','127.0.0.1','::','::1') -and $Domain -in $parts[1..($parts.Count-1)]) {return $true}
    }
    return $false
}
function Add-HostsBlockBytes([byte[]]$Bytes,[string[]]$Domains) {
    # Preserve the existing bytes, including a UTF-8/UTF-16 BOM. Refuse UTF-32.
    if ($Bytes.Length -ge 4 -and (($Bytes[0] -eq 255 -and $Bytes[1] -eq 254 -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0) -or ($Bytes[0] -eq 0 -and $Bytes[1] -eq 0 -and $Bytes[2] -eq 254 -and $Bytes[3] -eq 255))) {throw 'UTF-32 hosts file requires manual review.'}
    $enc=New-Object Text.UTF8Encoding($false)
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254) {$enc=[Text.Encoding]::Unicode}
    elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 254 -and $Bytes[1] -eq 255) {$enc=[Text.Encoding]::BigEndianUnicode}
    $text=$enc.GetString($Bytes);$missing=@($Domains | Where-Object {-not (Test-HostsBlocked $text $_)})
    if (-not $missing.Count) {return ,$Bytes}
    $tail="`r`n# BEGIN NIKKE Recovery Kit`r`n0.0.0.0 "+($missing -join ' ')+"`r`n:: "+($missing -join ' ')+"`r`n# END NIKKE Recovery Kit`r`n"
    return ,([byte[]]($Bytes+$enc.GetBytes($tail)))
}
function Copy-VerifiedEvidence([string]$Source,[string]$Destination,[string]$ExpectedHash) {
    Assert-NoReparse $Source;Assert-NoReparse $Destination
    if (Test-Path -LiteralPath $Destination) {throw 'Evidence destination already exists; never overwrite.'}
    $streams=@(Get-Item -LiteralPath ('\\?\'+(Get-CanonicalPath $Source)) -Stream * -ErrorAction Stop)
    if (-not $streams.Count) {throw 'Stream enumeration incomplete; source retained.'}
    $extraStreams=@($streams | Where-Object {$_.Stream -notin @(':$DATA','::$DATA')})
    if ($extraStreams.Count) {throw 'Extra NTFS streams require separate preservation; source retained, no automatic removal.'}
    $inputStream=[IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $hash=[Security.Cryptography.SHA256]::Create()
        try {$actual=([BitConverter]::ToString($hash.ComputeHash($inputStream))).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
        if ($ExpectedHash -and $actual -ine $ExpectedHash) {throw 'Source changed after identification.'}
        $inputStream.Position=0
        $outputStream=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$inputStream.CopyTo($outputStream);$outputStream.Flush()} finally {$outputStream.Dispose()}
        if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ine $actual) {throw 'Evidence copy failed hash verification.'}
    } finally {$inputStream.Dispose()}
    return $actual
}
function Move-IncidentFile([string]$Source,[string]$ProfileRoot,[string]$QuarantineRoot,[string]$ExpectedHash) {
    if (-not (Test-PathWithin $Source $ProfileRoot)) {throw 'Quarantine source outside profile.'}
    Assert-NoReparse $Source;Assert-NoReparse $QuarantineRoot
    if (Test-PathWithin $QuarantineRoot $Source) {throw 'Quarantine cannot be inside source.'}
    $dest=Join-Path $QuarantineRoot (([guid]::NewGuid().ToString('N'))+'.dll.quarantined')
    $verified=Copy-VerifiedEvidence $Source $dest $ExpectedHash
    if ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -ine $verified) {throw 'Source changed; original retained.'}
    # No recursive filesystem deletion: remove only the hash-verified selected file.
    Remove-Item -LiteralPath $Source -Force -ErrorAction Stop
    return [pscustomobject]@{Source=$Source;Preserved=$dest;SHA256=$verified;OriginalStillExists=(Test-Path -LiteralPath $Source)}
}
Export-ModuleMember -Function *

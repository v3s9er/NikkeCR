A small program I made in tears because I didn't want to format my PC.

# NIKKE Recovery Kit

[한국어](README-ko.md) | English

Version: `0.3.1-preview`

A Windows recovery aid that checks for the malicious DLL, per-user registry persistence, and launcher caches associated with the NIKKE PC launcher compromise. It preserves originals before isolating identified artifacts and inventories installed programs and startup references for follow-up review.

**This tool is intended to help when formatting a PC is difficult. It cannot guarantee that reinstalling Windows is unnecessary or certify that the entire PC is safe.** It is an unofficial preview that still needs further validation.

## Usage

### Preparation

Use 64-bit Windows with Windows PowerShell 5.1 or PowerShell 7. The `Run-*.cmd` launchers use the Windows PowerShell 5.1 installation included with Windows. Extract the complete ZIP into a local folder; do not mix files from different packages or move individual files out of it.

Keep launcher logs and caches until you have inspected them: they may contain evidence of infection and timing. Save your work and fully close the NIKKE launcher before applying repairs.

### Audit → repair → verify

1. **Run `Run-Audit.cmd`:** reads the current state and creates an evidence folder. It does not apply repairs.
2. **Review the results:** inspect `REPORT.txt`, `summary.json`, and `plan.json` for the verdict, errors, target paths, and proposed actions.
3. **Run `Run-Repair.cmd`:** after Windows administrator approval, applies network blocks, removes eligible per-user persistence entries, quarantines identified DLLs, and preserves launcher caches. Apply inspects the current state again, so its action list may differ from an earlier audit.
4. **Run `Run-Verify.cmd`:** checks for remaining known indicators, loaded DLLs, and areas that could not be inspected. It does not apply new repairs.
5. If the result is `AffectedApplicationExitRequired`, save your work, fully exit the listed application, and verify again. If a file lock prevented quarantine, run repair again after closing that application.

Results are stored in a separate folder for each run under `%LOCALAPPDATA%\NikkeRecovery\Evidence`. Previous evidence is not overwritten.

| File | What to check |
|---|---|
| `REPORT.txt` | Summary verdict and proposed actions |
| `summary.json` | Action successes and failures, remaining indicators, and inspection errors |
| `plan.json` | Repair actions proposed by that run |
| `before.json`, `after.json` | Observations before and after the run |
| `post-recovery-inventory.json` | Installed programs, startup references, referenced files, and coverage |
| `program-recovery-plan.json` | Follow-up checks for each program |
| `EVIDENCE-SHA256.json` | Integrity hashes for result files |
| `preserved` | Preserved originals and backups; may contain malware |

An invisible or unapproved administrator prompt does not mean repair completed. The tool does not forcibly close applications or restart Windows.

### Custom paths

First use the default audit to check package integrity. Then open a 64-bit PowerShell session in the tool folder and specify the actual installation path.

```powershell
.\Invoke-NikkeRecovery.ps1 -Mode Plan -LauncherRoots 'D:\Games\NIKKE\Launcher'

# After reviewing the plan, run in an administrator PowerShell session
.\Invoke-NikkeRecovery.ps1 -Mode Apply -LauncherRoots 'D:\Games\NIKKE\Launcher'

# Verify using the same installation path
.\Invoke-NikkeRecovery.ps1 -Mode Verify -LauncherRoots 'D:\Games\NIKKE\Launcher'
```

Specify another user with `-TargetProfile 'C:\Users\OtherUser'`. That user's registry hive must already be loaded; the tool does not load it automatically. When elevation uses a different administrator account, the default launcher still passes the originally selected target profile.

### Compare later observations

After restarting an application or rebooting Windows yourself, collect a new audit and compare it with an earlier inventory.

```powershell
.\New-NikkeFollowUp.ps1 -InventoryPath 'C:\Evidence\after\post-recovery-inventory.json' -PreviousInventoryPath 'C:\Evidence\before\post-recovery-inventory.json'
```

The generated `snapshot-differences.json` records changes to startup paths and arguments, referenced file hashes, browser policies, and registered program versions. `AbsentFromLaterSnapshot` means an item was not observed in the later inventory. Incomplete coverage can cause this, so it does not prove successful removal. Two identical inventories are not a trusted pre-infection baseline.

## Aftercare

### Run once or schedule checks

Run `Run-Aftercare.cmd` to recheck known incident indicators and compare the inventory with the previous observation. The default output directory is `%LOCALAPPDATA%\NikkeRecovery\Aftercare`. Open `STATUS.html` for the latest status and each run's `aftercare.json` for changes and post-reboot observations.

```powershell
# Save a schedule plan without registering it
.\Register-NikkeAftercare.ps1 -Mode Plan -Hours 6 -Notify

# Read-only checks three minutes after this user logs in and every six hours
.\Register-NikkeAftercare.ps1 -Mode Install -Hours 6 -Notify

# Inspect the schedule / remove only the tool-owned task
.\Register-NikkeAftercare.ps1 -Mode Status
.\Register-NikkeAftercare.ps1 -Mode Remove
```

The task runs with the current user's limited privileges while that user is logged in. It stores no password and does not run as `SYSTEM`. Overlapping runs for the same user are blocked, and scheduled execution is restricted on battery power. The first timed trigger is approximately five minutes after registration. Existing tasks are not overwritten: review and remove a task before installing a changed schedule. If you move the tool directory, register the task again with the new path.

With `-Notify`, the tool attempts a Windows notification for a new review state. Windows notification settings can hide it, so also inspect `STATUS.html` and `notification.json`. Nothing is transmitted externally. Scheduled checks do not repair or delete files automatically, or start Defender full scans.

Changed startup references or files remain pending until reviewed; an unchanged subsequent snapshot does not silently dismiss them. To acknowledge reviewed changes, supply the exact `AlertSignature` from the latest `aftercare.json`.

```powershell
.\Invoke-NikkeAftercare.ps1 -AcknowledgeChanges -ExpectedAlertSignature 'REPLACE_WITH_CURRENT_ALERT_SHA256'
```

This records acknowledgement of snapshot changes only. It does not dismiss known malicious indicators or vendor-baseline mismatches. Failed inspections retain the previous observation and display a failure status.

### Compare against a vendor package

The supported reference format is a **vendor ZIP package with the same version and file layout**. Verify the package and SHA-256 through an official distribution channel first. Hashing an arbitrary downloaded ZIP does not make it an official original. `OperatorPinnedArchive` means the baseline matches the operator-selected package; `PublisherAuthenticityVerified=false` means the tool has not independently authenticated the publisher.

Replace the paths, version, URL, and hashes below. If the ZIP has a top-level folder, specify it with an option such as `-ArchivePrefix 'ExampleApp'`.

```powershell
# Build a file baseline without executing anything in the ZIP
.\Manage-NikkeIntegrity.ps1 -Mode Baseline -PackagePath 'C:\Downloads\ExampleApp-1.0.zip' -PackageSHA256 'REPLACE_WITH_TRUSTED_PACKAGE_SHA256' -ProgramName 'ExampleApp' -ProgramVersion '1.0' -SourceUri 'https://vendor.example/downloads/ExampleApp-1.0.zip'

# Use the baseline.json path and SHA256 printed by the preceding command
.\Manage-NikkeIntegrity.ps1 -Mode Plan -BaselinePath 'C:\Evidence\baseline.json' -BaselineSHA256 'REPLACE_WITH_BASELINE_SHA256' -TargetRoot 'C:\Tools\ExampleApp'
```

The plan distinguishes matching, mismatched, missing, and unreadable files. Extra executable files absent from the package are flagged for review. Legitimate updates can also produce mismatches; check the installed version first. ZIP limits are 2 GiB compressed, 1 GiB total uncompressed, 128 MiB per file, and 20,000 entries. Archives containing traversal paths, duplicate paths, or symbolic links are refused.

### Preserve and repair selected files

Supply pinned hashes for both the baseline and the plan, and explicitly select relative paths to replace. The command below uses `-WhatIf` to describe the selection without applying it. Remove `-WhatIf` only after review. The actual Apply operation revalidates the package and target files.

```powershell
.\Manage-NikkeIntegrity.ps1 -Mode Apply -BaselinePath 'C:\Evidence\baseline.json' -BaselineSHA256 'REPLACE_WITH_BASELINE_SHA256' -PlanPath 'C:\Evidence\integrity-plan.json' -PlanSHA256 'REPLACE_WITH_PLAN_SHA256' -PackagePath 'C:\Downloads\ExampleApp-1.0.zip' -RelativePath 'bin\app.dll' -OutputRoot 'C:\Evidence\NikkeRepair' -WhatIf
```

Only explicitly selected `.exe`, `.dll`, `.ocx`, `.pyd`, and `.node` files are eligible. Configuration and user-data files are not replaced. Existing originals are preserved in a verified copy and an atomic-replacement backup; the replacement is hashed afterward. Keep repair evidence outside the application directory, on the same volume. A changed or locked target records a failure and stops subsequent replacements. No automatic rollback restores potentially malicious originals.

Windows system files, MSIX-managed directories, and execution of arbitrary MSI or EXE installers are outside this replacement feature. Applications requiring vendor servicing or configuration recovery need separate handling. Restart the repaired application, compare it against the same baseline, and collect aftercare results again. Even after an observed reboot, coverage gaps or pending review items retain `InconclusiveAfterRestart`.

### Include selected program baselines in scheduled checks

Create a configuration such as the following and retain its SHA-256 separately. Each run supports up to five programs, with a 30-second processing-loop budget for each.

```json
{
  "Schema": 1,
  "Checks": [
    {
      "BaselinePath": "C:\\Evidence\\baseline.json",
      "BaselineSHA256": "REPLACE_WITH_BASELINE_SHA256",
      "TargetRoot": "C:\\Tools\\ExampleApp"
    }
  ]
}
```

```powershell
.\Invoke-NikkeAftercare.ps1 -BaselineConfigPath 'C:\Evidence\aftercare-baselines.json' -BaselineConfigSHA256 'REPLACE_WITH_CONFIG_SHA256'
```

The same two arguments can be passed to `Register-NikkeAftercare.ps1 -Mode Install`. This checks selected program files; it does not automatically acquire trusted originals for every installed application. Monitoring runs after login and at scheduled intervals, rather than watching every file in real time or updating itself.

## Results and limitations

### Reading verdicts

| Verdict | Meaning |
|---|---|
| `KnownIndicatorsRemain` | A known active DLL or eligible registry persistence entry remains |
| `AffectedApplicationExitRequired` | A process has a DLL with the relevant name loaded; exit the application and check again |
| `ReviewRequired` | Unverified candidates, read failures, coverage gaps, or protection-state issues need review |
| `NoKnownActiveIndicatorsWithinScope` | No known active indicators were found within the inspected scope; this is not a whole-PC safety verdict |

Every result retains `WholeHostCleanClaim: false`. Exit code `0` means the run ended without a recorded repair-action failure, not that the PC is uninfected. Code `2` indicates a failed repair action or one skipped because it no longer matches the reviewed plan, `1` a startup or reporting error, and `1223` a cancelled administrator prompt. Some Windows launch paths also report cancelled elevation as `1`.

If the original cannot be removed after a verified copy is preserved, both files remain. Quarantine is incomplete. Check the action outcomes in `summary.json` and the original path.

### What this tool cannot resolve

- The attacker could run commands to install additional programs or modify other files. This tool focuses on known artifacts from this incident; it cannot find and reverse every unknown secondary payload or change.
- An inventory of installed programs and executable references is not a comparison of every program file against trusted vendor originals. Programs remain `NotIntegrityVerified` until that separate comparison is completed. Signatures not checked by the bulk inventory remain `NotChecked`.
- Protected processes, unloaded user hives, unselected user files, non-default installation paths, portable or MSIX applications, drivers, shortcut destinations, and script arguments may be missed.
- A filename, directory name, size, or LuaJIT header alone does not establish malware. A different hash does not establish that a file is clean. False-positive and false-negative rates have not been measured on a sufficiently representative corpus.
- The malicious `l.js` served during the investigated infection and the exact Lua payload downloaded on that PC were not recovered. Files from other dates and the analyzed `k2f.lua` do not fill every gap.
- The tool cannot recover or invalidate stolen passwords, cookies, sessions, API tokens, or SSH keys. Account recovery, session revocation, and necessary credential replacement must be handled separately from a trusted device.
- A clean antivirus scan or a no-match result cannot rule out the need to reinstall Windows. Removing known artifacts without formatting does not prove that the machine has returned completely to its pre-infection state.

### Coverage and time limits

| Inspection | Default limits |
|---|---|
| Lua candidates | Selected launcher logs and caches plus the user's Temp directory; 16 MiB per file; up to 10,000 files and 5,000 directories; depth 8; 60-second processing loop |
| Referenced executable hashes | Up to 750 files; 64 MiB per file; 120-second processing loop |
| Post-recovery inventory | Separate read-only worker; 180-second deadline |

Loop budgets do not guarantee immediate interruption of an individual operating-system file read. If the inventory worker exceeds its deadline, only that worker is stopped and committed partial results are recovered. Check `WorkerCompleted=false`, errors, and skipped items. Files missing from partial results, or without hashes, remain unexamined.

## How it works

### 1. Package integrity and inspection

The default launcher checks the version, required file list, and SHA-256 hashes in `PACKAGE-SHA256.json` before starting inspection. The manifest detects damage and mismatches; it does not authenticate the publisher like a digital signature.

The tool reads DLLs, Lua candidates, registry entries, caches, loaded modules, and containment state. It also inventories installed programs, Run/RunOnce entries, scheduled tasks, services, startup folders, browser policies, WMI subscriptions, and referenced executables. Inspection and plan generation do not repair or remove arbitrary programs.

### 2. DLL and Lua identification

A DLL matching the SHA-256 of the directly analyzed specimen is classified as `Confirmed`. For a different hash, `StrongMatch` requires a PE DLL, the specified Chrome directory structure, and all five strings below.

```text
analytics.insightjs.com/px/
Debugger.paused
Debugger.scriptParsed
Runtime.callFunctionOn
WinHttpSendRequest
```

`StrongMatch` is a strict combined heuristic, not proof of complete binary equivalence. A matching filename alone, or the normal `platform_experience_helper.exe`, does not authorize removal.

A matching LuaJIT format and both substitution-table patterns produce `SuspectedK2f` for further analysis. A file under `log\tinyget`, with a numeric date/time-shaped `tinyget.*.log` name and a size of 205,135 bytes, produces `OfficialTinygetReview`. This review condition comes from the [official manual security-check notice](https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7); it does not prove malicious content or execution.

Lua classification is read-only. Files inside a launcher cache selected for isolation are preserved with that cache, but Lua files elsewhere are not automatically deleted. The release contains neither a Lua interpreter nor malware specimens.

### 3. Network containment and persistence removal

`Apply` blocks the known attacker IPs in Windows Firewall and adds domain blocks to `hosts`. It also blocks discovered NIKKE launcher executables. Existing sufficient blocks are reused. These blocks may prevent normal gameplay and are not automatically removed.

Registry cleanup is limited to the incident CLSID under the target user's registry. Entries pointing to an identified DLL, and known empty per-user overrides, are backed up before removal. Unexpected targets or subkeys are retained for review. The normal `HKLM` registration is not modified.

### 4. Evidence preservation and quarantine

For a DLL, the tool verifies the SHA-256 of a preserved copy and rechecks that the original has not changed before removing it from its original location. For launcher caches, it records relative paths, sizes, and hashes, moves the directory to an evidence location on the same volume, and compares the result.

Evidence-folder access is limited to the relevant user, `SYSTEM`, and `Administrators`. Boundary escapes, UNC paths, reparse points, and disallowed alternate data streams are rejected or left for manual review. Preservation or quarantine failures are not reported as success.

### 5. Post-recovery verification

The tool reads the state again after repair and reports remaining indicators and failures. Per-program follow-up plans support further file and configuration review against trusted originals. They do not execute arbitrary repair commands from the registry or reinstall every application automatically.

## Malware hashes and key indicators

These SHA-256 values identify files. File presence, execution, and actual data theft are separate findings.

| File | Size | SHA-256 | Evidence and implementation |
|---|---:|---|---|
| `platform_experience_helper.dll` | 250,368 bytes | `10e722777685e290e8fd5370d4c5cd1a40d0d7e91b93af0156faefe18467a3f1` | Directly recovered and statically analyzed DLL; included in exact-hash detection |
| `insight.bundle` | 205,135 bytes | `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` | Reference hash published by `MotherSphere`; not included in this tool's exact-hash list |

Published specimen hashes and build differences are documented in [MotherSphere's analysis](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5#indicators-of-compromise). Different builds can share the same size; size alone does not identify an exact specimen.

| Indicator | Value and meaning |
|---|---|
| Per-user COM registration | `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` |
| DLL location | `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<SHA256>\platform_experience_helper.dll`, where `<SHA256>` is a 64-character hexadecimal directory name |
| Launcher caches | `tbs_cache` under `nikke_launcher`, `nikke_launcher_hmt`, or `nikke_launcher_google` in `AppData\Roaming` and `AppData\Local` |
| Investigative log references | `k2f_chan registered`, `k2f.agent.state`; listing these strings does not imply that this tool implements a general log or LevelDB parser |
| Blocked domains | `insightjs.com`, `analytics.insightjs.com`, `insightjs.org` |
| Blocked IPs | `89.127.233.127`, `89.126.250.172` |

The tool does not broadly delete or patch the normal `PlatformExperienceHelper` directory, Chrome extensions or wallet data, game executables, or Windows system files. The addresses above are for identification and blocking; there is no need to visit them.

## Validation status and evidence handling

On each of Windows PowerShell 5.1 and PowerShell 7.6.5, 32 core, 31 extended, 39 aftercare/integrity, 6 package-preflight, 10 inert CLI workflow, and 4 worker-receipt cases passed. The combined 244 case executions use inert files and simulated inspection inputs; they are not repairs of infected PCs.

Windows Task Scheduler validated the generated task XML without registering a task. A Microsoft-signed Procmon64.exe was also compared read-only against its previously acquired official ZIP. Actual scheduled execution and visible notification delivery remain untested.

Reports may contain private paths and command arguments, while `preserved` may contain malware originals. Keep distributable tool ZIPs separate from private run results. Do not execute preserved files or blindly restore registry backups.

The tool has no remote upload, telemetry, automatic update, or malware-execution feature. It does not change antivirus settings or exclusions, or automatically start Defender full or offline scans. The launcher's `ExecutionPolicy Bypass` applies only to its child PowerShell process.

## Sources and credits

- **[MotherSphere](https://github.com/MotherSphere)** — author of the [NIKKE PC launcher compromise Gist](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5). The attack-chain analysis, indicators, and follow-up investigations in the comments informed this work.
- **[MotherSphere / NIKKE-Launcher-Check](https://github.com/MotherSphere/NIKKE-Launcher-Check)** — the read-only detection tool linked from the Gist, consulted when comparing detection scope and reporting behavior.
- **[zbeosf's Gist comment](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5?permalink_comment_id=6456219#gistcomment-6456219)** — public indicators and the command list for a Lua build were used as references.
- **[NIKKE / Level Infinite](https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7)** — the official manual security-check notice used to compare paths and the file-size review condition.
- **[Microsoft Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertask)** — documentation for validating task definitions without registration. File replacement also follows the [.NET File.Replace documentation](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace).
- **v3s9er_PC** — source of the directly recovered DLL, launcher caches and logs, registry and system records, and their independent analysis. Personal investigation records and malware originals are excluded.

Credits acknowledge references and contributions. They do not imply joint development, review, or a safety endorsement by the credited authors.

## License

This project's code and documentation are distributed under the **MIT License**. See [LICENSE](LICENSE) for the full terms.

Use, copying, modification, distribution, and commercial use are permitted subject to retaining the copyright and license notice. The software is provided without warranty. The MIT text states the exact terms.

External projects, analysis materials, and malware specimens retain their own rights and licenses. This project's MIT declaration does not change those licenses.

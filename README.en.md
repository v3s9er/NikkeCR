A small program made through tears because I did not want to format my PC.

# NikkeCR

[한국어](README.md) · **English** · [MIT License](LICENSE)

A Windows tool for investigating known traces of the NIKKE PC launcher compromise and preserving evidence before targeted recovery. Open `NikkeCR.exe` and use **탐지 (Detect)** or **복구 (Repair)**. The **실행로그 (Execution log)** tab shows progress and failures. The interface currently uses Korean.

**Version: 0.4.4-preview. This is not a guarantee of complete remediation, a complete reconstruction of exfiltration, or a replacement for reinstalling a compromised system when necessary.**

## Executable location

**[Download the Windows executable ZIP](https://github.com/v3s9er/NikkeCR/releases/download/v0.4.4-preview/NikkeCR-0.4.4-preview-win-x64.zip)** → extract it → run **`NikkeCR\NikkeCR.exe`**.

For example, extracting into `C:\Tools` places the executable at **`C:\Tools\NikkeCR\NikkeCR.exe`**. Keep `scripts`, `engine`, `data`, and the hash manifest beside the executable.

**[NikkeCR.exe](NikkeCR.exe) is also included at the repository root.** To download the repository, use **Code → Download ZIP**, extract the complete folder, and run `NikkeCR-main\NikkeCR.exe`. Downloading the EXE alone omits the required scripts and integrity manifest.

## Usage

1. Download the Windows x64 ZIP from [Releases](https://github.com/v3s9er/NikkeCR/releases), extract it to a local folder without synchronization/reparse points, and keep the executable, scripts, engine, data and hash manifest together.
2. Run `NikkeCR\NikkeCR.exe` from the extracted folder and select **탐지**. Enable administrator detection for broader event-log and process access, then approve the standard Windows UAC prompt.
3. Optionally provide a preserved evidence folder containing original launcher logs. An optional HAR input can provide historical HTTP evidence. The tool does not reconstruct missing network packets or treat generated analysis reports as original execution records.
4. Review findings and coverage gaps. Select **복구**, review its concrete plan, and approve UAC to preserve, block, isolate and verify supported items.
5. If a DLL remains loaded, save work, fully exit the affected application, then detect again. Applications are not force-closed and Windows is not automatically rebooted.

Reports, logs and backups remain in the selected user's `%USERPROFILE%\NikkeCR-Evidence\Runs\<run ID>`. Review `result.json`, `report.html`, `progress.log`, `history.json`, `settings.json`, and the engine evidence directory. These local files can contain personal information; do not upload the entire folder publicly. The program does not upload reports, run a Defender full scan, decrypt real passwords or send telemetry.

## Interpreting results

| State | Meaning |
| --- | --- |
| Captured transfer · amber | The supplied HAR contains the known endpoint, POST body, nonempty value and 2xx response. Capture authenticity and originating computer remain unverified, so it is not automatically attributed to this PC. Values are hashed. |
| Confirmed exfiltration · red | Reserved for evidence supporting both host attribution and transmitted contents. This version does not automatically generate this state from a HAR alone. |
| Known threat · orange | Current DLL, COM registration or module-loading indicators. Exact hashes and combined structural heuristics are distinguished in the evidence. |
| Potential exposure · orange | A statically targeted path exists. Presence does not prove collection or transmission. |
| Collection trace · orange | A filename matches a known staging pattern. Contents, provenance and transmission remain unconfirmed. |
| Review / coverage gap | Unexplained execution relationships, access failures, disabled logs or collection limits. These do not become clean results. |
| Verified repair | The specific action passed its follow-up check. This does not establish whole-host safety. |

**Zero confirmed exfiltration findings does not mean no theft occurred.** DNS, connections, SRUM byte counts and agent counters cannot establish which files or accounts were stolen.

## Operation and scope

- Checks the known DLL SHA-256 and strict combined structural indicators, the known user COM override, mapped modules and Lua structural leads. It does not remove the entire legitimate Chrome helper directory.
- [The static capability catalog](data/static-capabilities.json) describes 100 services, 220 unique paths, additional Lua collectors and 28 DLL wallet targets. Analysis covers 277 Lua function entries, 14 registered commands and 703 DLL function entries. Enumeration is not proof that every path executed.
- Separates developer/cloud credentials, browser logins and cookies, saved NIKKE credentials, screenshots, system information, arbitrary files and command output. The catalog check reads path metadata rather than credential values.
- Inventories installed programs, startup links, tasks, service/driver registrations, WMI, browser policies and bounded referenced-file hashes. Reads Sysmon, Security, System, TaskScheduler, Application and DNS logs. Uses available `ProcessGuid` relationships rather than joining unrelated processes solely by PID.
- Checks original launcher `debug.log` startup markers and known staging filenames. Original logs may still be incomplete or tampered with. Each event source is limited to the latest 3,000 relevant records since 2026-09-27; gaps and truncation are reported.
- Repair performs supported network containment, user COM cleanup, hash-verified DLL preservation/quarantine and launcher-cache preservation/isolation. Newly discovered actions outside the reviewed detection plan are skipped. Launcher blocking can prevent game connectivity.
- Additional settings repair is restricted to a user PAC URL pointing at a known attacker domain or a user Run/RunOnce entry directly referencing the exact known DLL hash. It preserves the value and type, checks for changes and verifies removal. Other proxy, policy and service settings require review.
- Package hashes detect changes relative to the manifest. They do not authenticate the publisher or establish trust in an already compromised host. The executable is currently unsigned.

## Aftercare and limitations

The GUI does not reinstall every application or reset all settings. Without a trusted version-matched original or pre-infection baseline, it cannot determine the correct replacement. The included [advanced engine documentation](engine/README.md) describes separately operated baseline and selected-file recovery using a validated same-version vendor ZIP. These features are not an automatic repair of every installed program.

`engine/Invoke-NikkeAftercare.ps1` can compare snapshots and maintain an unreviewed-change ledger. Scheduled monitoring is not installed automatically; consult the engine's registration and removal instructions. Revoke credentials, tokens, SSH keys and sessions separately from a trusted device.

The exact local Lua payload and historical malicious `l.js` were not recovered. The statically analyzed Lua is not proven identical to the locally executed build. Arbitrary `exec` activity, unknown payloads, other users, custom profiles, deleted evidence, kernel/firmware compromise and every application dependency remain outside a complete clean-host claim. Direct SRUDB/USN parsing and deleted-file recovery are not implemented. Missing historical request bodies cannot be recreated by a retrospective scan.

## Malware identifiers

| File | SHA-256 | Evidence |
| --- | --- | --- |
| `platform_experience_helper.dll` | `10e722777685e290e8fd5370d4c5cd1a40d0d7e91b93af0156faefe18467a3f1` | Independent static analysis of the DLL recovered from `v3s9er_PC` |

A filename or size alone does not identify the specimen. Raw malware and personal investigation records are not distributed in this repository or release.

## Sources and acknowledgments

- **[MotherSphere](https://github.com/MotherSphere)** — [NIKKE PC launcher compromise Gist](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5), public indicators, attack-chain documentation and follow-up findings.
- **[MotherSphere / NIKKE-Launcher-Check](https://github.com/MotherSphere/NIKKE-Launcher-Check)** — consulted when comparing read-only detection scope. Its code was not copied into this MIT project.
- **[zbeosf's Gist comment](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5?permalink_comment_id=6456219#gistcomment-6456219)** — public indicators and the command list for a Lua build were used as references.
- **v3s9er_PC** — source of the directly recovered DLL, launcher caches and logs, registry and system records, and the independent analysis correlating them. Originals and personal investigation records are not distributed.

Attribution identifies contributions, not malware authorship.

## Build and validation

Requires Windows x64, Windows PowerShell 5.1 and .NET Framework. From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Build.ps1 -Package
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-NikkeCR.ps1
```

After building, the executable is `NikkeCR.exe` at the repository root, and the package is `dist\NikkeCR-0.4.4-preview-win-x64.zip`.

The build uses the installed .NET Framework compiler without downloading packages. [Validation notes](docs/VALIDATION.md) distinguish performed checks from outstanding work.

## License

Original NikkeCR code is distributed under the [MIT License](LICENSE). This does not relicense malware, third-party analysis material or external projects.

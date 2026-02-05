# Notepad++ WinGUp Updater Hijack (Lotus Blossom / Chrysalis) - Hunt Playbook

## Executive summary
Notepad++ said its WinGUp updater traffic was sometimes redirected to malicious servers during a hosting-provider compromise. Rapid7 ties the malicious update payloads to the Lotus Blossom group and documents a custom backdoor (Chrysalis) plus a loader chain that uses BluetoothService.exe + log.dll sideloading. Reporting says the campaign targeted government, telecom, aviation, and critical infrastructure organizations, mainly in Southeast Asia and Central America. The fix in v8.8.9 enforces signature and certificate checks, so endpoints on versions earlier than 8.8.9 that used WinGUp are the main exposure set. This playbook focuses on exposure validation, suspicious update chains, and post-update activity.

OSINT timeline (abridged)
- 2025-06 (approx): Attackers gain access to hosting-provider infrastructure; selective redirection begins (reported).
- 2025-09-02: Hosting provider maintenance removed direct server access; credentials persisted (reported).
- 2025-11-18: Notepad++ v8.8.8 released; manual upgrade guidance.
- 2025-12-02: Credentials rotated; attacker access terminated (reported).
- 2025-12-09: Notepad++ v8.8.9 released with enforced signature/certificate validation for updates.
- 2025-12-17: F5 threat report summarizes forum-reported AutoUpdater.exe behavior and temp.sh exfil details (secondary).
- 2025-12-27: Notepad++ v8.9 released with `securityError.log` for update validation failures.
- 2026-02-02: Notepad++ incident update published; Rapid7 releases Chrysalis deep-dive.

## Objective
- Identify endpoints that were vulnerable at the time of potential hijack and confirm whether a suspicious update chain occurred.
- Detect malicious or unusual installer writes/executions tied to Notepad++ updater activity.
- Surface post-update behavior consistent with malicious payload execution (Chrysalis loader chain or reported recon/exfil).
- Focus effort on hosts that actually updated during the window; version inventory alone is not enough.

## Hypothesis
If WinGUp traffic was redirected for an endpoint, we should see: (1) Notepad++ pre-8.8.9 installed, (2) GUP.exe or Notepad++ writing an installer, (3) an installer execution chain that looks wrong, and (4) follow-on suspicious activity (BluetoothService.exe + log.dll, AutoUpdater.exe in Temp, recon commands).

## Risk if true
- Silent delivery and execution of a compromised installer (user-level code execution).
- Potential for follow-on privilege escalation, credential access, or lateral movement depending on host controls.
- Compromise likely limited to a subset of endpoints based on update timing and selective redirection.

## Scope
- In-scope: Windows endpoints with Notepad++ installed.
- Priority scope: Notepad++ versions < 8.8.9 (especially active users who recently updated).
- Time window: 2025-06-01 onward for update-chain analysis; tighten if you can bound updates by patch cycles.

## Data sources
- EDR process creation telemetry (ProcessRollup2 / SyntheticProcessRollup2).
- File write telemetry (PeFileWritten / FileWritten / FileDetectInfo).
- Installed application inventory (InstalledApplication).
- DNS telemetry (DnsRequest / SuspiciousDnsRequest) for update domain visibility.
- Network telemetry (if available) for outbound HTTPS to api.skycloudcenter.com.
- Module or image load telemetry (if available) to spot unusual clipc.dll loads by non-system binaries.

## MITRE ATT&CK mapping
- T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain (Updater hijack). Indicator: updater traffic redirected to deliver a poisoned installer via the official update mechanism.
- T1105 - Ingress Tool Transfer (malicious installer delivery). Indicator: WinGUp downloads and writes a new installer binary that is then executed locally.
- T1036 - Masquerading (payload mimics legitimate installer/update). Indicator: installer naming consistent with official `npp.<version>*.exe/.msi` patterns but not matching known-good hashes.
- T1059 - Command and Scripting Interpreter (post-update recon). Indicator: recon commands such as `netstat`, `systeminfo`, `tasklist`, `whoami` observed after updater activity.
- T1574.002 - Hijack Execution Flow: DLL Search Order Hijacking (log.dll sideloading via BluetoothService.exe).
- T1027.007 - Obfuscated Files or Information: Dynamic API Resolution (API hashing). Indicator: hashed API lookups in Chrysalis/loader variants (secondary reporting).
- T1106 - Native API (NtQuerySystemInformation use by loader variants).
- T1620 - Reflective Code Loading (loader variants executing decrypted shellcode).
- Secondary reporting maps this campaign to additional ATT&CK techniques, including T1204.002, T1027, T1140, T1055, T1059.003, T1083, T1005, T1041, T1071.001, T1573, T1547.001, T1543.003, T1480.002, and T1070.004.

## Hunt approach (with challenge checks)
1) **Exposure inventory**
   - Identify endpoints with Notepad++ versions < 8.8.9.
   - Challenge: Are version fields normalized? Are portable installs missing from inventory?

2) **Updater activity + installer writes**
   - Find GUP.exe or Notepad++ processes that write `npp.*.exe` or `.msi` installers.
   - Challenge: Are we excluding legitimate enterprise packaging tools or software management agents?
   - If file-write telemetry is limited, pivot to DNS + process creation around update times.

3) **Suspicious installer execution chain**
   - Look for installer execution from Temp/AppData or unusual parent processes.
   - Challenge: Do we have a baseline of known-good installer parents (e.g., GUP.exe)?

4) **Chrysalis loader chain indicators (Rapid7)**
   - Hunt for hidden `%AppData%\Bluetooth` directories, BluetoothService.exe + log.dll co-resident, and BluetoothService.exe executing outside its expected path.
   - Watch for loader variants like ConsoleApplication2.exe or s047t5g.exe in user-writable paths (reported).
   - If you have module-load telemetry, look for clipc.dll loaded by a non-system binary from a user-writable path.
   - Challenge: Are there any legitimate Bitdefender tools named BluetoothService.exe in your environment?

5) **Post-update behavior (reported but not globally confirmed)**
   - Hunt for `%Temp%\AutoUpdater.exe`, recon commands, and `curl.exe` uploads to `temp.sh`.
   - Challenge: Are we over-indexing on a single report? Treat as supporting signals only.

6) **Correlate with DNS or network artifacts (optional)**
   - Look for `notepad-plus-plus.org` DNS from GUP.exe/Notepad++.
   - Look for GUP.exe DNS to non-Notepad++/GitHub domains or HTTPS to `api.skycloudcenter.com` or `api.wiresguard.com`.
   - Challenge: DNS visibility may be limited; do not treat absence as safe.
   - Tie any C2 domains back to the updater process tree before escalating.

## LogScale queries
Moved to: [Notepad++ WinGUp LogScale queries](LotusBlossom_Billbug_Notepad++_hijack_Logscale_queries.md)

## Expected outcomes
- List of endpoints running Notepad++ < 8.8.9.
- Subset of endpoints with suspicious updater-driven installer writes.
- Subset with anomalous installer execution chains or Chrysalis loader chain artifacts.
- Detection rules as code.

## Triage and response tips
- Validate whether suspicious installer writes align with user-initiated updates or enterprise software deployment windows.
- Inspect installer file metadata (signer, timestamp) and compare to official release expectations.
- If BluetoothService.exe/log.dll or AutoUpdater.exe is seen, prioritize endpoint isolation and artifact collection.
- Prioritize hosts where you can prove both the update chain and post-update artifacts; single-signal hits are noisy.

## False positives / tuning notes
- Legitimate enterprise packaging tools may write/install Notepad++.
- Portable installs may bypass standard installer/EDR signals.
- DNS-only visibility without process correlation is weak; prefer joined signals.

## Validation
- Cross-check installer SHA256 against known-good release hashes when available.
- Confirm signer chain for installer and binaries (GlobalSign for 8.8.7+).
- Review update logs or Notepad++ `securityError.log` on v8.9+ for failed validation attempts.
- Capture full process trees for GUP.exe/update.exe and any loader variants to avoid false attribution.

## Investigation checklist (IR handoff)
- Preserve installer artifacts (`npp.*.exe` / `.msi`) and compute hashes; capture signer chain and file timestamps.
- Export process tree for installer execution (parents/children), plus any BluetoothService.exe/log.dll or AutoUpdater.exe activity.
- Collect `%LOCALAPPDATA%\Notepad++\log\securityError.log` (if v8.9+ installed).
- Pull DNS and network connections around update events (process-linked if possible).
- Acquire Windows event logs, EDR detections, and any software deployment logs for the timeframe.
- If suspicious activity confirmed, capture memory and triage persistence locations on affected hosts.

## Containment
- Isolate endpoints with confirmed suspicious update chains or payload execution.
- Reinstall Notepad++ from trusted sources and remove any untrusted certificates.
- Rotate credentials if post-update recon indicates broader compromise.

## Deliverables
- Exposure inventory by Notepad++ version.
- Suspicious update chain findings (with process + file evidence).
- Chrysalis loader chain and post-update behavioral findings (if any).

## Exit criteria
- No evidence of suspicious installer writes/execution on exposed endpoints in the time window.
- No post-update anomalous behavior tied to Notepad++ update chain.
- All exposed endpoints upgraded to 8.8.9+ and verified.

## Static IOCs (use as supporting signals, not primary detections)
From public reporting (Rapid7 + secondary writeups):
- `%AppData%\Bluetooth\BluetoothService.exe` and `%AppData%\Bluetooth\log.dll`
- `api.skycloudcenter.com` (Chrysalis C2)
- `api.wiresguard.com` (reported C2 for loader variants)
- update.exe SHA-256: a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9
- BluetoothService.exe SHA-256: 2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924
- log.dll SHA-256: 3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad
- ConsoleApplication2.exe (reported loader variant)
- libtcc.dll, conf.c, u.bat (reported staging artifacts)
- `%Temp%\AutoUpdater.exe` spawned by GUP.exe or Notepad++ updater chain
- Files named `update.exe` in user TEMP where GUP.exe wrote or executed the file
- Recon commands: `netstat -ano`, `systeminfo`, `tasklist`, `whoami`
- Exfil staging file: `a.txt` (temp location reported)
- Exfil destination domain: `temp.sh` via `curl.exe`
- GUP.exe network requests to domains other than `notepad-plus-plus.org`, `github.com`, or `release-assets.githubusercontent.com`

Note: Notepad++ did not publish malicious hashes. Rapid7 published specific hashes; treat all third-party IoCs as incident-specific until validated.

## IOC JSON mapping
Source of truth for indicators: [LotusBlossom_Billbug_Notepad++_hijack_IOCs.json](LotusBlossom_Billbug_Notepad++_hijack_IOCs.json)
- Fields: `indicator`, `type`, `attributed_to`, `source_urls`, `confidence`, `tactic_or_use`, `notes`
- Coverage includes filenames, domains, URLs, IPs, hashes, and behavioral heuristics with source attribution
- Caution: indicators are incident-reported; validate with process lineage, signer metadata, and time alignment before action.

### Source-to-IOC map (quick reference)
| Source | IoCs / behaviors cited |
| --- | --- |
| Notepad++ v8.8.9 release notice | Baseline update domains and hardened validation (no malicious hashes) |
| Notepad++ hijacked incident info update | Incident update context; reinforces update-chain risk and mitigations |
| Notepad++ community thread (topic 27212) | AutoUpdater.exe in TEMP, temp.sh upload URL, update.exe, sample command lines |
| F5 threat report (Dec 17, 2025) | AutoUpdater.exe, recon commands, temp.sh exfil, a.txt staging |
| BleepingComputer recap (Dec 11, 2025) | temp.sh exfil, recon command list, updater URL format |
| Kevin Beaumont (DoublePulsar) | Suspicious GUP.exe network to non-official domains |
| NCSA alert (Rwanda) | Affected versions < 8.8.9 and malicious updater activity warning |
| Heise recap | Suspicious updater behavior and non-standard child processes |
| Security Affairs recaps | Targeting context and updater weakness discussion (secondary) |
| ThreatHuntingFather (Telegram) | Additional community-reported indicators; treat as secondary |
| Rapid7 Chrysalis report | update.exe, BluetoothService.exe/log.dll, C2 domain, hashes |

## IOC validation checklist (analyst appendix)
- Verify the process chain: confirm updater/installer parentage and whether execution context matches user-initiated updates.
- Validate file metadata: signer, compile timestamp, and file path consistency with known-good Notepad++ releases.
- Check hash reputation: compare against official release hashes and internal allowlists before escalation.
- Correlate with behavior: link IoCs to post-update activity (recon, suspicious network, persistence) to avoid false positives.
- Confirm time alignment: ensure IoC hits occur during the suspected hijack window and near update events.
- Preserve evidence: capture binaries, logs, and process trees for IR review if suspicion remains.

## References
OSINT summary: LotusBlossom_Billbug_Notepad++_hijack_OSINT_Report.md

Notepad++ release notes and public reporting:
```text
https://notepad-plus-plus.org/news/v889-released/
https://notepad-plus-plus.org/news/v89-released/
https://notepad-plus-plus.org/news/v888-released/
https://notepad-plus-plus.org/news/hijacked-incident-info-update/
https://www.bleepingcomputer.com/news/security/notepad-plus-plus-fixes-flaw-that-let-attackers-push-malicious-update-files/
https://securityaffairs.com/185622/hacking/notepad-fixed-updater-bugs-that-allowed-malicious-update-hijacking.html
https://securityaffairs.com/187531/security/nation-state-hack-exploited-hosting-infrastructure-to-hijack-notepad-updates.html
https://cyber.gov.rw/updates/article/security-alert-notepad-update-vulnerability-enables-malware-installation/
https://cybersecuritynews.com/notepad-hijacked/
https://thehackernews.com/2026/02/notepad-official-update-mechanism.html
https://cybernews.com/security/notepad-plus-plus-updater-compromised/
https://hackmag.com/news/notepad-bug
https://www.techworm.net/2025/12/notepad-fixes-major-update-flaw-that-let-attackers-push-malware.html
https://community.notepad-plus-plus.org/topic/27212/autoupdater-and-connection-temp-sh
https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9
https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
https://t.me/ThreatHuntingFather/1130
https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
```

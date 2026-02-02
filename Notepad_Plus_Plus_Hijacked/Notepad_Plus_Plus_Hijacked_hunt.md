# Notepad++ WinGUp Updater Hijack - Hunt Playbook

## Executive summary
Notepad++ reported that its WinGUp updater traffic was occasionally redirected to malicious servers, enabling delivery of compromised executables. The fix in v8.8.9 enforces signature and certificate checks, meaning endpoints running versions prior to 8.8.9 that used WinGUp are the exposure set. This playbook focuses on validating exposure, identifying suspicious update chains, and hunting for post-update execution consistent with malicious payload delivery.

OSINT timeline (abridged)
- 2025-11-18: Notepad++ v8.8.8 released after identifying a potential WinGUp hijacking issue; manual upgrade recommended.
- 2025-12-09: Notepad++ v8.8.9 released with enforced signature/certificate validation for updates.
- 2025-12-27: Notepad++ v8.9 released with `securityError.log` for update validation failures.
- 2025-12-17: F5 threat report summarizes forum-reported AutoUpdater.exe behavior and temp.sh exfil details (secondary).
- 2026-02-02: Additional reporting alleges state-sponsored activity, selective redirection, and hosting-provider level compromise (unconfirmed).
- Reported onset (unconfirmed): June 2025, with selective targeting claims in secondary reporting.

## Objective
- Identify endpoints that were vulnerable at the time of potential hijack and confirm whether a suspicious update chain occurred.
- Detect malicious or anomalous installer writes/executions tied to Notepad++ updater activity.
- Surface post-update behavior consistent with malicious payload execution.

## Hypothesis
If WinGUp updater traffic was redirected for an endpoint, we should observe: (1) Notepad++ pre-8.8.9 installed, (2) GUP.exe (or Notepad++) initiating an installer write, (3) the installer execution chain deviating from known-good patterns, and (4) follow-on suspicious process activity (e.g., AutoUpdater.exe in Temp or recon commands).

## Risk if true
- Silent delivery and execution of a compromised installer (user-level code execution).
- Potential for follow-on privilege escalation, credential access, or lateral movement depending on host controls.
- Compromise may be localized to a subset of endpoints based on update timing and redirection.

## Scope
- In-scope: Windows endpoints with Notepad++ installed.
- Priority scope: Notepad++ versions < 8.8.9 (especially active users who recently updated).
- Time window: 2025-11-01 onward for update-chain analysis; expand if evidence suggests earlier/later impact.

## Data sources
- EDR process creation telemetry (ProcessRollup2 / SyntheticProcessRollup2).
- File write telemetry (PeFileWritten / FileWritten / FileDetectInfo).
- Installed application inventory (InstalledApplication).
- DNS telemetry (DnsRequest / SuspiciousDnsRequest) for update domain visibility.

## MITRE ATT&CK mapping
- T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain (Updater hijack). Indicator: updater traffic redirected to deliver a poisoned installer via the official update mechanism.
- T1105 - Ingress Tool Transfer (malicious installer delivery). Indicator: WinGUp downloads and writes a new installer binary that is then executed locally.
- T1059 - Command and Scripting Interpreter (if recon commands executed). Indicator: post-update recon commands such as `netstat`, `systeminfo`, `tasklist`, `whoami` observed after updater activity.
- T1036 - Masquerading (malicious installer mimicking legitimate update). Indicator: installer naming consistent with official `npp.<version>*.exe/.msi` patterns but not matching known-good hashes.

## Hunt approach (with challenge checks)
1) **Exposure inventory**
   - Identify endpoints with Notepad++ versions < 8.8.9.
   - Challenge: Are version fields normalized? Are portable installs missing from inventory?

2) **Updater activity + installer writes**
   - Find GUP.exe or Notepad++ processes that write `npp.*.exe` or `.msi` installers.
   - Challenge: Are we excluding legitimate enterprise packaging tools or software management agents?

3) **Suspicious installer execution chain**
   - Look for installer execution from Temp/AppData or unusual parent processes.
   - Challenge: Do we have a baseline of known good installer parents (e.g., GUP.exe)?

4) **Post-update execution indicators (reported but not confirmed globally)**
   - Hunt for `%Temp%\AutoUpdater.exe`, recon command execution (netstat/systeminfo/tasklist/whoami), and `curl.exe` uploads to `temp.sh`.
   - Challenge: Are we over-indexing on a single report? Treat as supporting signal only.

5) **Correlate with DNS or network artifacts (optional)**
   - Look for `notepad-plus-plus.org` DNS from GUP.exe/Notepad++.
   - Look for GUP.exe DNS to non-Notepad++/GitHub domains (reported as suspicious in Beaumont guidance).
   - Challenge: DNS visibility may be limited or centralized; do not treat absence as safe.

## LogScale queries
Moved to: [Notepad++ WinGUp LogScale queries](Notepad_Plus_Plus_Hijacked_Logscale_queries.md)

## Expected outcomes
- List of endpoints running Notepad++ < 8.8.9.
- Subset of endpoints with suspicious updater-driven installer writes.
- Subset with anomalous installer execution chains or suspicious post-update activity.
- Detection rules as code.

## Triage and response tips
- Validate whether suspicious installer writes align with user-initiated updates or enterprise software deployment windows.
- Inspect installer file metadata (signer, timestamp) and compare to official release expectations.
- If AutoUpdater.exe or recon commands are seen, prioritize endpoint isolation and artifact collection.

## False positives / tuning notes
- Legitimate enterprise packaging tools may write/install Notepad++.
- Portable installs may bypass standard installer/EDR signals.
- DNS-only visibility without process correlation is weak; prefer joined signals.

## Validation
- Cross-check installer SHA256 against known-good release hashes when available.
- Confirm signer chain for installer and binaries (GlobalSign for 8.8.7+).
- Review update logs or Notepad++ `securityError.log` on v8.9+ for failed validation attempts.

## Investigation checklist (IR handoff)
- Preserve installer artifacts (`npp.*.exe` / `.msi`) and compute hashes; capture signer chain and file timestamps.
- Export process tree for installer execution (parents/children), plus any AutoUpdater.exe activity.
- Collect `%LOCALAPPDATA%\\Notepad++\\log\\securityError.log` (if v8.9+ installed).
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
- Post-update behavioral findings (if any).

## Exit criteria
- No evidence of suspicious installer writes/execution on exposed endpoints in the time window.
- No post-update anomalous behavior tied to Notepad++ update chain.
- All exposed endpoints upgraded to 8.8.9+ and verified.

## Static IOCs (use as supporting signals, not primary detections)
From public reporting (F5 threat report and secondary writeups, based on forum-reported incidents):
- `%Temp%\\AutoUpdater.exe` spawned by `GUP.exe` or Notepad++ updater chain
- Files named `update.exe` in user TEMP where GUP.exe wrote or executed the file
- Recon commands: `netstat -ano`, `systeminfo`, `tasklist`, `whoami`
- Exfil staging file: `a.txt` (temp location reported)
- Exfil destination domain: `temp.sh` via `curl.exe`
- GUP.exe network requests to domains other than `notepad-plus-plus.org`, `github.com`, or `release-assets.githubusercontent.com`

Note: No authoritative list of malicious hashes or payload C2 infrastructure has been published by Notepad++. Treat third-party IoCs as incident-specific until validated.

## IOC JSON mapping
Source of truth for indicators: [Notepad_Plus_Plus_Hijacked_IOCs.json](Notepad_Plus_Plus_Hijacked_IOCs.json)
- Fields: `indicator`, `type`, `attributed_to`, `source_urls`, `confidence`, `tactic_or_use`, `notes`
- Coverage includes filenames, domains, URLs, IPs, and behavioral heuristics with source attribution
- Caution: indicators are incident-reported; validate with process lineage, signer metadata, and time alignment before action.
- Note: no public malicious hashes were published in reviewed sources; treat any hashes you find as environment-specific until corroborated.

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

## IOC validation checklist (analyst appendix)
- Verify the process chain: confirm updater/installer parentage and whether execution context matches user-initiated updates.
- Validate file metadata: signer, compile timestamp, and file path consistency with known-good Notepad++ releases.
- Check hash reputation: compare against official release hashes and internal allowlists before escalation.
- Correlate with behavior: link IoCs to post-update activity (recon, suspicious network, persistence) to avoid false positives.
- Confirm time alignment: ensure IoC hits occur during the suspected hijack window and near update events.
- Preserve evidence: capture binaries, logs, and process trees for IR review if suspicion remains.

## References
OSINT summary: Notepad_Hijacked_OSINT_Report.md

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
```

F5 threat reporting (supporting indicators):
```text
https://www.f5.com/labs/articles/threat-intelligence/notepadplusplus-updater-hijack
```

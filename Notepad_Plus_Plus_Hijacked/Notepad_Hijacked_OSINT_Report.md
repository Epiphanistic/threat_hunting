# Notepad++ Updater Hijack (WinGUp) OSINT Report
Date: 2026-02-02

## Executive Summary
- Notepad++ confirmed that WinGUp updater traffic was occasionally redirected to malicious servers, enabling delivery of compromised executables.
- The core weakness was insufficient update validation; v8.8.9 enforces signature and certificate checks and aborts updates on failure.
- Affected scope is any system running Notepad++ versions prior to v8.8.9 that used WinGUp during periods of redirection.
- The exact hijacking method remains unconfirmed; public reporting includes MITM/redirection theories but no definitive root cause.

## Incident Overview (What is confirmed)
- WinGUp update traffic was occasionally redirected to malicious servers, resulting in compromised executables being downloaded.
- v8.8.9 introduced mandatory signature and certificate validation for update installers.
- Since v8.8.7, Notepad++ binaries are signed with a GlobalSign certificate; older custom root certificates should be removed.
- v8.9 adds a `securityError.log` for update validation failures.

## Timeline (from public sources)
- 2025-11-18: Notepad++ v8.8.8 released with mitigation guidance (manual upgrade; updates only from GitHub).
- 2025-12-02: Kevin Beaumont notes a small number of incidents tied to Notepad++ update activity (secondary reporting).
- 2025-12-09: Notepad++ v8.8.9 released with hardened signature/certificate validation.
- 2025-12-11: BleepingComputer incident recap highlights AutoUpdater.exe, recon commands, and temp.sh exfil details.
- 2025-12-17: F5 threat report summarizes forum-reported behavior and temp.sh exfil details.
- 2025-12-27: Notepad++ v8.9 released with `securityError.log` for update validation failures.
- 2026-02-02: Additional reporting alleges state-sponsored activity and selective redirection (unconfirmed).

## Attack Path (likely mechanics)
- Reported cases indicate the update URL (`https://notepad-plus-plus.org/update/getDownloadUrl.php`) may have been hijacked to redirect the updater to malicious downloads.
- Prior to v8.8.9, an update validation weakness could allow an attacker-in-the-middle to replace the installer with a malicious executable.

## Impact & Blast Radius Analysis
### Impact (technical)
- If a user accepted or auto-ran a malicious update, the attacker would gain code execution in the user context.
- Reported cases describe AutoUpdater.exe executing recon commands and exfiltrating output to temp.sh; use these as supporting signals and validate locally.

### Blast Radius (who is exposed)
- **Directly exposed endpoints:** Windows systems running Notepad++ < v8.8.9 and using WinGUp during the hijack window.
- **Scope modifiers:** Exposure depends on whether traffic was intercepted for a given network/ISP/region; Notepad++ described redirection as occasional.
- **Targeting indicators (unconfirmed):** Some reporting cites a small number of organizations in East Asia, suggesting targeted activity.

## Detection & Validation Guidance
- Check Notepad++ version fleet-wide; prioritize upgrades from any version earlier than 8.8.9.
- Review `securityError.log` on v8.9+ endpoints for update validation failures.
- Review endpoint telemetry for suspicious execution chains involving Notepad++ or updater components spawning unexpected executables (e.g., `%Temp%\AutoUpdater.exe`).
- Community forum reports and Beaumont’s write-up highlight `AutoUpdater.exe`/`update.exe` in TEMP and DNS/HTTP to `temp.sh` as supporting indicators; validate against local telemetry.

## Mitigations & Hardening
- Upgrade to v8.8.9+ to enforce signature/certificate validation in WinGUp.
- Remove any previously installed Notepad++ root certificate; GlobalSign is the current signer.
- Restrict updater traffic to trusted sources and monitor for unexpected redirects or download domains.

## Open Questions / Gaps
- The root cause of redirection (network MITM vs. server-side compromise) has not been publicly confirmed.
- No authoritative public list of malicious payload hashes or C2 infrastructure has been published.

## Additional Reporting (Unconfirmed / Secondary)
- Security Affairs and The Hacker News discuss targeted activity and hosting-provider compromise claims; these remain unverified.
- Heise recap describes updater-installed malware and suspicious updater activity; secondary reporting only.

## Sources (OSINT)
- Notepad++ v8.8.8 release notice: https://notepad-plus-plus.org/news/v888-released/
- Notepad++ v8.8.9 release notice: https://notepad-plus-plus.org/news/v889-released/
- Notepad++ v8.9 release notice: https://notepad-plus-plus.org/news/v89-released/
- Rwanda NCSA alert: https://cyber.gov.rw/updates/article/security-alert-notepad-update-vulnerability-enables-malware-installation/
- BleepingComputer recap: https://www.bleepingcomputer.com/news/security/notepad-plus-plus-fixes-flaw-that-let-attackers-push-malicious-update-files/
- F5 threat report: https://community.f5.com/kb/security-insights/f5-threat-report---december-17th-2025/344787
- Kevin Beaumont (DoublePulsar): https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9
- Security Affairs (Dec 2025 recap): https://securityaffairs.com/185622/hacking/notepad-fixed-updater-bugs-that-allowed-malicious-update-hijacking.html
- Security Affairs (Feb 2026 recap): https://securityaffairs.com/187531/security/nation-state-hack-exploited-hosting-infrastructure-to-hijack-notepad-updates.html
- The Hacker News: https://thehackernews.com/2026/02/notepad-official-update-mechanism.html
- Cybernews: https://cybernews.com/security/notepad-plus-plus-updater-compromised/
- Cybersecurity News: https://cybersecuritynews.com/notepad-hijacked/
- HackMag: https://hackmag.com/news/notepad-bug
- TechWorm: https://www.techworm.net/2025/12/notepad-fixes-major-update-flaw-that-let-attackers-push-malware.html
- Heise: https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
- Notepad++ community forum thread: https://community.notepad-plus-plus.org/topic/27212/autoupdater-and-connection-temp-sh

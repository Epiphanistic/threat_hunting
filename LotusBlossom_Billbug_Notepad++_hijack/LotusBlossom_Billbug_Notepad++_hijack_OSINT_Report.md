# Lotus Blossom / Billbug Notepad++ Update Hijack (WinGUp / Chrysalis) OSINT Report
Date: 2026-02-03

## Executive Summary
- Rapid7 links a custom backdoor (Chrysalis) to Lotus Blossom/Billbug and says it was delivered through hijacked Notepad++ updates.
- Reports point to a compromise at the hosting provider that let attackers redirect WinGUp update traffic for selected users.
- Notepad++ hardened updates in v8.8.9 (signature + certificate checks) and added `securityError.log` in v8.9.
- Exposure is mainly Windows endpoints running Notepad++ < 8.8.9 that used WinGUp during the compromise window.
- Reporting says the campaign targeted government, telecom, aviation, and critical infrastructure organizations, mainly in Southeast Asia and Central America.
- Bottom line: treat this as a selective supply‑chain incident. The best signal is the updater chain plus post‑update artifacts, not broad IOCs alone.

## Incident Overview (What is confirmed)
- Update traffic was selectively redirected to malicious servers (reported by multiple sources).
- The compromise was at the hosting-provider layer, not a Notepad++ source-code breach.
- v8.8.9 introduced mandatory signature and certificate checks for update installers.
- Since v8.8.7, Notepad++ binaries are signed with GlobalSign; older custom root certificates should be removed.
- v8.9 adds `securityError.log` for update validation failures.
- Rapid7 documented a custom backdoor (Chrysalis) and loader chain delivered via the hijacked update path.

## Timeline (from public sources)
- 2025-06 (approx): Attackers gain access to shared hosting infrastructure; selective redirection begins.
- 2025-09-02: Hosting provider maintenance removed direct server access; credentials persisted.
- 2025-11-18: Notepad++ v8.8.8 released with mitigation guidance (manual upgrade; updates from GitHub).
- 2025-12-02: Credentials rotated; attacker access fully terminated.
- 2025-12-02: Kevin Beaumont reports a small number of incidents tied to Notepad++ update activity (secondary reporting).
- 2025-12-09: Notepad++ v8.8.9 released with enforced certificate/signature validation.
- 2025-12-11: BleepingComputer recap highlights AutoUpdater.exe, recon commands, temp.sh exfil details.
- 2025-12-17: F5 threat report summarizes forum-reported behavior and temp.sh exfil details.
- 2025-12-27: Notepad++ v8.9 released with `securityError.log` for update validation failures.
- 2026-02-02: Notepad++ incident update published; Rapid7 releases Chrysalis deep-dive.
- 2026-02-03: Additional non-English coverage and translations (Japan/China).

## Attack Path (likely mechanics)
- The update URL (`https://notepad-plus-plus.org/update/getDownloadUrl.php`) was reportedly hijacked to redirect the updater to malicious downloads.
- Before v8.8.9, weak update validation could allow a man-in-the-middle to replace the installer.
- Rapid7 reports the execution chain: notepad++.exe -> GUP.exe -> update.exe (downloaded from 95.179.213.0).
- update.exe is described as an NSIS installer that deployed a DLL sideloading chain:
  - BluetoothService.exe (renamed Bitdefender Submission Wizard) + malicious log.dll
  - Encrypted shellcode embedded in BluetoothService
- The installer created a hidden %AppData%\Bluetooth directory and executed BluetoothService.exe, which loaded log.dll and decrypted shellcode, leading to Chrysalis execution.
- Chrysalis C2: api.skycloudcenter.com (Rapid7 reports DNS resolution to 61.4.102.97 during analysis; observed C2 path includes `/a/chat/s/{GUID}`).
- Additional reporting notes custom encryption (linear congruential generator), API hashing (FNV-1a + MurmurHash-style finalizer), and a C2 URL structure that mimics Deepseek API endpoints.
- Some reporting also mentions a loader variant (ConsoleApplication2.exe) that uses Microsoft Warbird and a `NtQuerySystemInformation` call (SystemCodeFlowTransition 0xB9) to execute shellcode in a way that may bypass user‑mode hooks.
- The Warbird loader reportedly uses a Microsoft-signed binary (clipc.dll) to trigger code decryption and execution in kernel context.

## Impact & Blast Radius Analysis
### Impact (technical)
- A trojanized update gives user-level code execution and a full-featured backdoor.
- Chrysalis performs host profiling and C2 over HTTPS.
- Reporting notes Chrysalis supports ~16 commands, including interactive shell, file operations, process execution, and self-removal.
- Some reports mention AutoUpdater.exe running recon commands and sending output to temp.sh; treat as supporting signals.
- Additional reporting lists loader variants and second‑stage artifacts that may appear alongside Chrysalis (see IoCs below).
- Expect many clean hosts to show nothing; this campaign was selective and time‑bounded, so absence of IOCs is not proof of safety.

### Blast Radius (who is exposed)
- **Directly exposed endpoints:** Windows systems running Notepad++ < 8.8.9 using WinGUp during the hijack window.
- **Scope modifiers:** Exposure depends on whether traffic was intercepted for a given network/ISP/region; Notepad++ described redirection as occasional.
- **Targeting indicators (unconfirmed):** Some reporting cites a small number of organizations in East Asia, suggesting targeted activity.

## Detection & Validation Guidance
- Check Notepad++ versions fleet-wide; prioritize upgrades from any version earlier than 8.8.9.
- Review `securityError.log` on v8.9+ endpoints for update validation failures.
- Hunt for update-chain anomalies: GUP.exe spawning unexpected %Temp%\AutoUpdater.exe or update.exe.
- Review endpoint telemetry for:
  - Hidden %AppData%\Bluetooth directory creation
  - BluetoothService.exe + log.dll on disk
  - Outbound HTTPS to api.skycloudcenter.com
  - Outbound HTTPS/DNS to api.wiresguard.com (reported loader C2)
- Community forum reports and Beaumont’s write-up highlight AutoUpdater.exe/update.exe in TEMP and DNS/HTTP to temp.sh; validate against local telemetry.
- Rapid7 IoCs (SHA-256):
  - update.exe: a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9
  - [NSIS].nsi: 8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e
  - BluetoothService.exe: 2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924
  - BluetoothService (shellcode): 77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e
  - log.dll: 3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad
- Additional reported file hashes (secondary reporting):
  - u.bat: 9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600
  - conf.c: f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a
  - libtcc.dll: 4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906
  - admin: 831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd
  - loader1: 0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd
  - uffhxpSy: 4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8
  - loader2: e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda
  - 3yzr31vk: 078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5
  - ConsoleApplication2.exe: b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3
  - system: 7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd
  - s047t5g.exe: fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a
  - Reported C2 domain for associated loader: api.wiresguard.com
  - Reported C2 IPs: 59.110.7.32, 124.222.137.114
- Confidence tiers for triage:
  - High: update.exe + BluetoothService.exe + log.dll chain with matching hashes or pathing.
  - Medium: unexpected GUP.exe installer writes + Temp/AppData execution + outbound C2 to api.skycloudcenter.com.
  - Low: temp.sh or recon commands without the update chain.

## Mitigations & Hardening
- Upgrade to Notepad++ v8.8.9+ to enforce certificate and signature validation for WinGUp installers.
- Remove any previously installed Notepad++ custom root certificates; GlobalSign is the current signer from v8.8.7 onward.
- Prefer manual downloads from official sources during incident response; monitor for unexpected redirects or download domains.

## Open Questions / Gaps
- The root cause of redirection (network MITM vs. server-side compromise) has not been publicly confirmed.
- Targeting logic and victim selection criteria have not been disclosed.
- Publicly confirmed malicious hashes are limited to those disclosed by Rapid7; additional variants may exist.
- There is no authoritative list of impacted orgs or IP ranges, so scoping has to be telemetry‑driven.

## Sources (OSINT)
### Primary / Vendor
- Rapid7 (Chrysalis backdoor deep dive): https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
- F5 Threat Report (Dec 17, 2025): https://community.f5.com/kb/security-insights/f5-threat-report---december-17th-2025/344787
- WA Cyber Security Unit advisory (Dec 15, 2025): https://soc.cyber.wa.gov.au/advisories/20251215002-NotepadPlusPlus-Traffic-Hijacking-Vulnerability/
- Wiz Threats (Feb 2, 2026): https://threats.wiz.io/all-incidents/supply-chain-hijacking-of-notepad-updates-via-hosting-provider-compromise
- Field Effect (Feb 2, 2026): https://fieldeffect.com/blog/chinese-linked-actors-notepad-update

### Official Notepad++
- Notepad++ v8.8.8 release: https://notepad-plus-plus.org/news/v888-released/
- Notepad++ v8.8.9 release: https://notepad-plus-plus.org/news/v889-released/
- Notepad++ v8.9 release: https://notepad-plus-plus.org/news/v89-released/
- Notepad++ hijacked incident info update: https://notepad-plus-plus.org/news/hijacked-incident-info-update/

### Government / CERT
- Rwanda NCSA alert: https://cyber.gov.rw/updates/article/security-alert-notepad-update-vulnerability-enables-malware-installation/

### News / Media
- Reuters (via Investing.com mirror): https://www.investing.com/news/economy-news/popular-opensource-coding-application-targeted-in-chineselinked-supplychain-attack-4479841
- TechCrunch (Feb 2, 2026): https://techcrunch.com/2026/02/02/notepad-says-chinese-government-hackers-hijacked-its-software-updates-for-months/
- The Verge (Feb 2, 2026): https://www.theverge.com/tech/872462/notepad-plus-plus-server-hijacking
- The Hacker News: https://thehackernews.com/2026/02/notepad-official-update-mechanism.html
- BleepingComputer recap: https://www.bleepingcomputer.com/news/security/notepad-plus-plus-fixes-flaw-that-let-attackers-push-malicious-update-files/
- Security Affairs (Dec 2025 recap): https://securityaffairs.com/185622/hacking/notepad-fixed-updater-bugs-that-allowed-malicious-update-hijacking.html
- Security Affairs (Feb 2026 recap): https://securityaffairs.com/187531/security/nation-state-hack-exploited-hosting-infrastructure-to-hijack-notepad-updates.html
- Cybernews: https://cybernews.com/security/notepad-plus-plus-updater-compromised/
- Cybersecurity News: https://cybersecuritynews.com/notepad-hack/
- HackMag: https://hackmag.com/news/notepad-bug
- TechWorm: https://www.techworm.net/2025/12/notepad-fixes-major-update-flaw-that-let-attackers-push-malware.html
- Heise: https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html

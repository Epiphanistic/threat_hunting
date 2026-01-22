# AppSuite PDF Editor Backdoor and TamperedChef

## Executive summary
AppSuite PDF Editor is distributed via ad-driven download sites and
installs a trojanized PDF editor. The initial installer can appear
benign, then later activates a backdoor and credential theft capability
(TamperedChef) through update routines and command-line switches. This
hunt focuses on identifying affected endpoints, tracking update/exfil
stages, and correlating DNS activity with host detections.

## Risk if true
- Browser credential and cookie theft via DPAPI access to browser data.
- Data exfiltration to attacker-controlled infrastructure.
- Persistence via scheduled tasks and registry Run keys.
- Follow-on malware delivery through update or downloader stages.
- Ongoing backdoor access via command-line controlled routines.

## Hypothesis
If AppSuite PDF Editor is present, endpoints will show process activity
for `PDF Editor.exe` with specific `--cm` arguments, DNS activity to
known campaign domains, and persistence artifacts (scheduled tasks and
Run key). Some hosts will also have endpoint detections tied to the same
process or DNS window.

## Scope
- In-scope: Windows endpoints with process, DNS, and registry telemetry.
- Time window: 7-30 days for detections and DNS; 1 year for inventory.
- Out-of-scope: macOS/Linux endpoints without relevant telemetry.

## MITRE mapping
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1056.003 - Input Capture: Web Portal Capture
- T1041 - Exfiltration Over C2 Channel
- T1105 - Ingress Tool Transfer
- T1071.001 - Application Layer Protocol: Web Protocols

## Data sources
- EDR process execution and command-line telemetry.
- DNS and proxy logs.
- Windows registry and scheduled task creation logs.
- Endpoint detection summaries.

## Expected outcome
- Host inventory with `PDF Editor.exe` execution and `--cm` switches.
- DNS hit list for campaign domains and update/exfil endpoints.
- Correlated detections for hosts with known binaries and DNS activity.
- Remediation list for uninstall and persistence cleanup.

## LogScale queries
Moved to: [AppSuite PDF Editor LogScale queries](AppSuite_PDF_Editor_Logscale_queries.md)

## Indicators of compromise
### Domains (from dashboard and reports)
- download*.internetdownloadhub.biz
- download*.masterlifemastermind.net
- download*.pdfgj.com
- download*.apdft.online
- pdf-kiosk.com
- pdf-kiosk.net
- easyonestartpdf.com
- ltdpdf.net
- fileconverterdownload.com
- pdfworker.com
- getsmartpdf.com
- proonestartpdf.com
- proonestarthub.com
- pdfonestarthub.com
- pdfonestarttoday.com
- smartonestartpdf.com
- cdasynergy.net
- pdfscraper.com
- pdffacts.com
- *appsuites.ai
- pdf-tool.appsuites.ai
- vault.appsuites.ai
- sdk.appsuites.ai
- on.appsuites.ai
- log.appsuites.ai
- inst.productivity-tools.ai
- pdfts.site
- micromacrotechbase.com
- pdfartisan.com
- apdft.com
- apdft.online
- itpdf.net
- itpdf.com
- 9mdp5f.com
- advancedtransmitart.net
- click4pdf.com
- convertpdfplus.com
- onestartbrowser.com
- smartmanualspdf.com
- transmitcdnzion.com
- y2iax5.com
- abf26u.com
- mka3e8.com
- 5b7crp.com
- pdfmeta.com
- pdfreplace.com

### URLs
- hxxps://inst.productivity-tools.ai/status/InstallStart
- hxxps://inst.productivity-tools.ai/status/Download%20Complete
- hxxps://inst.productivity-tools.ai/status/InstallDownloadComplete
- hxxps://vault.appsuites.ai/AppSuite-PDF-1.0.28.exe

### File hashes (SHA256)
- PDF Editor.exe: cb15e1ec1a472631c53378d54f2043ba57586e3a28329c9dbf40cb69d7c10d2c
- PDFEditorSetup.exe: da3c6ec20a006ec4b289a90488f824f0f72098a2f5c2d3f37d7a2d4a83b344a0
- Uninstall PDF Editor.exe: 956f7e8e156205b8cbf9b9f16bae0e43404641ad8feaaf5f59f8ba7c54f15e24
- MSI: fde67ba523b2c1e517d679ad4eaf87925c6bbf2f171b9212462dc9a855faa34b
- pdfeditor.js: b3ef2e11c855f4812e64230632f125db5e7da1df3e9e34fdb2f088ebe5e16603
- UtilityAddon.node: 6022fd372dca7d6d366d9df894e8313b7f0bd821035dd9fa7c860b14e8c414f2
- Deobfuscated pdfeditor.js: 104428a78aa75b4b0bc945a2067c0e42c8dfd5d0baf3cb18e0f6e4686bdc0755

### Additional file hashes (MD5/SHA1)
- PDF Editor.exe MD5: 6fd6c053f8fcf345efaa04f16ac0bffe
- PDF Editor.exe SHA1: 2ecd25269173890e04fe00ea23a585e4f0a206ad

### Install locations
- %LOCALAPPDATA%\Programs\PDF Editor
- %USERPROFILE%\PDF Editor
- %USERPROFILE%\PDF Editor\resources\app\w-electron\bun\releases\pdfeditor.js

### Persistence and user agent
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PDFEditorUpdater
- Scheduled tasks: PDFEditorScheduledTask, PDFEditorUScheduledTask,
  ShiftLaunchTask, OneLaunchLaunchTask, WaveBrowser-StartAtLogin
- User agent: PDFFusion/93HEU7AJ

### Command-line switches
- --cm=--install
- --cm=--enableupdate
- --cm=--disableupdate
- --cm=--fullupdate
- --cm=--partialupdate
- --cm=--backupupdate
- --cm=--check
- --cm=--ping
- --cm=--reboot
- --cm=--cleanup

## Triage and response tips
- Confirm `PDF Editor.exe` parent process, path, and signer.
- Review command-line usage for `--cm` switches, especially
  `--fullupdate`, `--backupupdate`, `--ping`, and `--cleanup`.
- Pivot from DNS hits to process and network telemetry for downloads.
- Check browser data access and evidence of forced browser termination.
- Correlate detections with exfil/update DNS to prioritize hosts.

## Validation
- Validate install location and binary hash.
- Verify registry Run key and scheduled tasks for persistence.
- Confirm DNS destinations and whether they were blocked or sinkholed.
- Identify staging files such as `pdfeditor.js` in the expected path.

## Containment
- Uninstall AppSuite PDF Editor and remove persistence artifacts.
- Block known domains at DNS/proxy layers.
- Rotate credentials for impacted users and clear browser sessions.
- Add allowlist enforcement for software installs and browser add-ons.

## Deliverables
- Host list with process evidence, hashes, and persistence artifacts.
- DNS report for campaign domains and update/exfil endpoints.
- Remediation tracking and credential reset status.
- Detection tuning recommendations for `--cm` behaviors.

## Exit criteria
- No active endpoints with `PDF Editor.exe` in the environment.
- No DNS activity to known campaign domains in the monitoring window.
- Persistence keys and scheduled tasks fully removed.

## References
- https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis

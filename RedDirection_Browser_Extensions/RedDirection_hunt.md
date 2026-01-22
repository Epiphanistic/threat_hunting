# RedDirection Malicious Chrome/Edge Extensions

## Executive summary
Identify endpoints with known RedDirection browser extension IDs and related network indicators. The
campaign uses legitimate-looking Chrome and Edge extensions that quietly updated to include browser
hijacking and telemetry exfiltration. Use extension install/enable telemetry and DNS/proxy data to
find impacted endpoints and prioritize hosts with correlated detection events.

## Risk if true
- Browser hijacking and redirect-to-phishing or malware delivery.
- URL and browsing telemetry exfiltration to attacker infrastructure.
- Credential theft and session hijack via redirected login flows.
- Supply-chain style persistence via silent extension updates.
- Secondary malware infections after redirect or fake update prompts.

## Hypothesis
If RedDirection extensions are present and active on endpoints, we will observe extension install or
enablement events for specific extension IDs and DNS requests to known campaign domains. Some hosts
will also show endpoint detections within the same window as extension enablement.

## Scope
- In-scope: endpoints running Chrome or Edge with extension telemetry.
- Time window: 1 year for extension inventory; 7-30 days for DNS/proxy hits (adjust as needed).
- Out-of-scope: browsers without extension telemetry; mobile.

## MITRE mapping
- T1176 - Browser Extensions (Persistence, Defense Evasion)
- T1185 - Browser Session Hijacking (Credential Access)
- T1056.003 - Input Capture: Web Portal Capture (Credential Access)
- T1195 - Supply Chain Compromise (Initial Access)

## Data sources
- EDR telemetry for browser extension install/enable events.
- DNS logs and web proxy logs.
- Endpoint detection summaries for correlation.
- Asset inventory for browser versions and extension policies.

## Expected outcome
- Inventory of hosts with known malicious extension IDs enabled.
- DNS hit list for campaign domains, prioritized by recent activity.
- Correlated host detections within the extension enablement window.
- Triage list with owners, browsers, and remediation status.

## LogScale queries
Moved to: [RedDirection LogScale queries](RedDirection_Logscale_queries.md)

## Indicators of compromise
### Extension IDs (Chrome)
- kgmeffmlnkfnjpgmdndccklfigfhajen - Emoji keyboard online - copy&past your emoji.
- dpdibkjjgbaadnnjhkmmnenkmbnhpobj - Free Weather Forecast
- gaiceihehajjahakcglkhmdbbdclbnlf - Video Speed Controller - Video manager
- mlgbkfnjdmaoldgagamcnommbbnhfnhf - Unlock Discord - VPN Proxy to Unblock Discord Anywhere
- eckokfcjbjbgjifpcbdmengnabecdakp - Dark Theme - Dark Reader for Chrome
- mgbhdehiapbjamfgekfpebmhmnmcmemg - Volume Max - Ultimate Sound Booster
- cbajickflblmpjodnjoldpiicfmecmif - Unblock TikTok - Seamless Access with One-Click Proxy
- pdbfcnhlobhoahcamoefbfodpmklgmjm - Unlock YouTube VPN
- eokjikchkppnkdipbiggnmlkahcdkikp - Color Picker, Eyedropper - Geco colorpick
- ihbiedpeaicgipncdnnkikeehnjiddck - Weather

### Extension IDs (Edge)
- jjdajogomggcjifnjgkpghcijgkbcjdi - Unlock TikTok
- mmcnmppeeghenglmidpmjkaiamcacmgm - Volume Booster - Increase your sound
- ojdkklpgpacpicaobnhankbalkkgaafp - Web Sound Equalizer
- lodeighbngipjjedfelnboplhgediclp - Header Value
- hkjagicdaogfgdifaklcgajmgefjllmd - Flash Player - games emulator
- gflkbgebojohihfnnplhbdakoipdbpdm - Youtube Unblocked
- kpilmncnoafddjpnbhepaiilgkdcieaf - SearchGPT - ChatGPT for Search Engine
- caibdnkmpnjhjdfnomfhijhmebigcelo - Unlock Discord

### Network indicators
- admitab.com
- edmitab.com
- click.videocontrolls.com
- c.undiscord.com
- click.darktheme.net
- c.jermikro.com
- c.untwitter.com
- c.unyoutube.net
- admitclick.net
- addmitad.com
- admiitad.com
- abmitab.com
- admitlink.net

## Triage and response tips
- Validate the extension ID and status (enabled vs disabled) on the host.
- Review recent browser extension updates and policy changes.
- Pivot from DNS hits to proxy and process telemetry for redirect or download activity.
- Check for suspicious login activity after DNS hits to campaign domains.
- Prioritize hosts with detection summaries in the enablement window.

## Validation
- Confirm extension IDs via endpoint telemetry or browser policy inventory.
- Verify whether DNS requests were blocked or sinkholed and review response IPs.
- Inspect extension files for recent updates or signature changes.
- Review browser history for redirects to phishing or fake update pages.

## Containment
- Remove the extension(s) and clear browser storage/cache.
- Revoke active browser sessions and rotate credentials for impacted users.
- Block IoC domains at DNS/proxy layers.
- Enforce allowlist-based extension policies in Chrome and Edge.

## Deliverables
- Host list with extension IDs, first/last seen, and owner.
- DNS/proxy hit report for campaign domains.
- Remediation tracking and user notification status.
- Recommendations for extension governance controls.

## Exit criteria
- No active endpoints with the listed extension IDs.
- IoC domains blocked or monitored with alerting.
- Detections and policy controls in place for extension installs/updates.

## References
- https://www.koi.ai/blog/google-and-microsoft-trusted-them-2-3-million-users-installed-them-they-were-malware

# Lotus Blossom Notepad++ Attacker Infrastructure Analysis 
> **Scope:** Censys infrastructure analysis with OSINT support and hunting actions.
---
## Conclusion (Bottom Line - UP)
> **Summary:** Key patterns, rationale, and huntable behaviors.
---
Based on the Censys report - a network‑infrastructure focused analysis. It pivots on scan data, TLS (transport layer security) certificate reuse, and service exposure timelines tied to the Notepad++ compromise. (https://censys.com/blog/npp-infra)

There are meaningful behavioral patterns derived: infrastructure reuse with churn, TLS certificate reuse for pivots, short exposure windows, and staging‑to‑C2 (command and control) progression. 
Thus, we can plan proactive threat hunting activities both externally faced and internally faced to match.

### WHY ---> Actionable Threat Hunting Actions (Proactive, Future‑Facing) and TA Profiling
> **Action Focus:** External (Censys) and Internal (defender) hunts.
---
#### External (Internet‑facing, Censys‑driven)
> **Use Case:** Internet‑facing pivots and infra lifecycle tracking.
1. **Certificate‑reuse pivots (Chrysalis + CS‑like)**
Why: The report shows TLS certificate reuse across multiple hosts, a strong operator linkage signal when combined with time overlap and non‑standard ports.
Steps: pivot on TLS SHA‑256 fingerprints and serials; track reuse across IPs, ports, and ASNs; flag reuse within short windows. Specific pivots from the report include the Chrysalis C2 cert tied to api.skycloudcenter.com (observed on 61.4.102.97 and later on 160.250.93.48) and Cobalt Strike‑like TLS cert reuse across multiple hosts. Signals: same cert on multiple IPs within days or weeks; reuse on non‑standard ports.
2. **Service‑history churn scoring**
Why: Multiple hosts show rapid service flips and dark periods; churn scoring surfaces reusable staging assets and short exposure windows more reliably than snapshots.
Steps: compute churn score from service history (appearance/disappearance frequency); rank hosts by churn + cert change rate. Specific pattern: 95.179.213.0 flipping between SSH‑only, HTTP/HTTPS on non‑standard ports, and dark periods. Signals: SSH‑only → HTTPS on odd port → disappearance within weeks.
3. **Non‑standard port clustering**
Why: The campaign uses uncommon ports for TLS/HTTP services; clustering on those ports aligns with short exposure windows and C2 staging behavior.
Steps: search for TLS/HTTP on uncommon ports; cluster by cert/issuer/JA3 or banner patterns. Specific ports seen in the report: 8082, 17777, 8880, 9999, 23333, and RDP on 5633. Signals: multiple hosts exposing TLS on 17777/8880/9999 and sharing TLS artifacts.
4. **C2‑like TLS artifact detection**
Why: Censys notes TLS artifacts consistent with common C2 frameworks; template‑like cert fields (default subjects, short validity, or issuer==subject) map to C2 infrastructure behavior.
Steps: look for self‑signed or template‑like TLS fields; pivot on identical subject/issuer strings. Specific context: CS‑like TLS certificates noted by Censys on loader hosts. Signals: default‑looking subjects, short validity windows, repeated issuer fields across multiple hosts.
5. **Open directory staging detection**
Why: The report shows open directories with small binaries before C2 services appear, a clear staging→C2 progression marker.
Steps: search for open directory listings; extract file patterns; correlate with later TLS service exposure. Specific context: Censys notes 59.110.7.32 exposing open directories before Cobalt Strike listeners. Signals: small EXEs/APKs, numeric filenames, later transition to TLS listeners.
6. **Temporal overlap pivots**
Why: Cert reuse with overlapping uptime windows strengthens linkage beyond coincidental reuse, matching cert‑reuse pivot behavior.
Steps: correlate cert reuse with concurrent uptime; prioritize overlapping windows over sequential reuse. Specific logic: if Chrysalis cert appears on two IPs during the same week, treat as stronger linkage. Signals: cert reuse with overlapping Censys scan dates.
7. **Lifecycle transition tracking**
Why: The report documents hosts that shift roles (staging → C2 → dormant); tracking transitions operationalizes that behavior.
Steps: categorize roles (staging, C2, dormant); detect transitions within short windows; track sequences. Example: staging‑style open directory → CS‑like TLS listener → dark. Signals: open directory exposure followed by TLS listener and then disappearance within 30–60 days.

#### Internal 
> **Use Case:** Defender‑owned asset and endpoint monitoring.
---
##### Cloud Service Provider‑oriented (ASM and perimeter‑centric)
1. **Public attack surface drift monitoring (ASM (attack surface management) + CMDB (configuration management database))**
Why: Sudden service flips on your public IPs mirror the service‑churn pattern and can indicate staging or misconfiguration before C2 activity.
Steps: baseline your public IP ranges and expected services per asset, then alert on new services or port exposure not tied to a change ticket. Practical sources: ASM platform, CMDB, firewall change logs.
2. **Certificate inventory mismatch (PKI + ASM)**
Why: Unexpected or reused certs on your assets mirror the certificate‑reuse pivot behavior and indicate unauthorized TLS deployment.
Steps: compare live TLS certs on public services to your certificate inventory. Flag unknown issuers, unexpected SANs (subject alternative names), or cert reuse across unrelated assets. Practical sources: PKI inventory, ASM TLS scans, certificate transparency monitoring.
3. **Service history anomalies (ASM timelines)**
Why: Repeated service changes within short windows match the short exposure window behavior and can signal infrastructure repurposing.
Steps: track service flips over time per asset (e.g., SSH appears, HTTPS moves to odd port, then disappears). Prioritize assets with multiple flips in short windows. Practical sources: ASM service history, recurring perimeter scans.
4. **Unauthorized non‑standard port exposure (Firewall + ASM)**
Why: The report shows TLS/HTTP on uncommon ports; internal exposure on similar ports is a strong deviation signal tied to short‑window C2 staging behaviors.
Steps: alert on exposure of TLS/HTTP on non‑standard ports unless explicitly approved. Tie to asset owner and change windows to reduce noise. Practical sources: firewall rules, ASM scans, SOC allowlists.
5. **Open directory exposure triage (Web scanner + ASM)**
Why: Open directories with binaries are a staging hallmark in the report; finding them internally maps to staging activity before C2.
Steps: scan public web assets for open directories and content patterns (binaries, numeric filenames). Treat newly exposed directories as priority, especially on assets with recent service churn. Practical sources: web scanner, ASM.
6. **External pivot validation against internal estate (ASM + SIEM)**
Why: If external suspicious certs/IPs overlap your assets, that is a direct bridge between external infra behaviors and internal exposure.
Steps: when a suspicious cert or IP appears externally, check for any internal overlap in cert fingerprint, issuer, or service banner. If overlap exists, prioritize immediate validation with the asset owner. Practical sources: ASM, SIEM, PKI inventory.

##### Endpoint‑oriented (victim‑org focus)
These are host‑based detections that are vendor‑agnostic and apply across enterprise endpoints.
1. **Updater process network behavior baselining**
Why: Update‑chain redirection is a common supply‑chain technique; out‑of‑vendor domains from updater processes are an early and practical detection point.
Steps: alert when any updater process initiates outbound connections to domains outside its approved vendor and repository set, regardless of application.
2. **Process tree and integrity monitoring for updater flows**
Why: Malicious update chains often introduce unexpected child processes or unsigned binaries during installation, which is visible in process trees.
Steps: monitor updater process trees across the fleet to verify that updaters only spawn expected installer binaries with valid signatures and expected parent‑child relationships; alert on deviations.
3. **Update validation failure log monitoring**
Why: Many products log validation failures when update integrity checks fail; repeated failures can indicate interception or manifest tampering.
Steps: monitor product‑specific update validation failure logs (where available) for repeated errors and correlate to update activity windows.

## Detailed Analysis of the censys report and other related OSINT data
> **Evidence Pack:** Patterns, challenges, and mapped OSINT support.
---

### Behavioral Patterns, Challenges, And OSINT Support (Table View)

<div style="font-size: 0.85em; line-height: 1.3; overflow-x: auto">

| Behavioral pattern | Likelihood | Why likely (summary) | Supporting OSINT (supports pattern) | OSINT that supports challenges | Challenges / caveats |
| --- | --- | --- | --- | --- | --- |
| Reusable staging asset with service churn and certificate switching | 70% | Selective redirection and hosting‑provider compromise imply controlled, time‑bounded exposure. Kaspersky reports monthly infrastructure rotation consistent with churn. | [Notepad++ incident update](#osint-notepad); [Wiz incident summary](#osint-wiz); [TechCrunch](#osint-techcrunch); [Kaspersky press release](#osint-kaspersky-pr); [Kaspersky Securelist](#osint-securelist). | Censys notes new SSH host key. | Service churn is not proof of a single operator; reimaging or resale can mimic churn. Selective targeting does not prove continuous host ownership. |
| TLS certificate reuse as a pivot strategy | 75% | Rapid7 confirms Chrysalis C2 domain and host resolution, while Censys shows certificate reuse across hosts; together this is a strong pivot signal. | [Rapid7 Chrysalis report](#osint-rapid7); Censys host history. | Censys Cobalt Strike methodology. | Certificate reuse is suggestive, not definitive; shared templates or reuse by different operators can create the same artifact. |
| Short exposure windows and non‑standard ports | 65% | Kaspersky reports monthly infra rotation, aligning with Censys short‑lived service windows. | [Kaspersky press release](#osint-kaspersky-pr); [Kaspersky Securelist](#osint-securelist); Censys host history. | Censys scan‑data limits statement. | Scan gaps can create false short windows; Censys acknowledges incomplete visibility. |
| Staging to C2 progression on the same host | 60% | Update‑chain abuse and post‑update behaviors map to a staging phase followed by C2 activity, but continuity is weaker. | [Rapid7 Chrysalis report](#osint-rapid7); [F5 threat report](#osint-f5); [Kaspersky Securelist](#osint-securelist); [Notepad++ 8.8.9 release](#osint-npp-889); [Notepad++ 8.9 release](#osint-npp-89). | Censys host ownership limits. | A different operator could have reused the same host; continuity is not proven by scan data alone. |

### Details: Behavioral Patterns From The Censys Report (February 3, 2026)

1. **Reusable staging asset with service churn and certificate switching**
The host 95[.]179.213.0 repeatedly alternates between SSH‑only, short‑lived HTTP/HTTPS on non‑standard ports, brief VPN and IKE (internet key exchange) exposure, and then inactivity across February 2025 through January 2026. Censys explicitly characterizes it as a reusable staging asset rather than a single‑purpose C2 server. This assessment is based on the timeline and service swings. (https://censys.com/blog/npp-infra)  
Challenge/Caveat: Service churn is not proof of a single operator. Service changes can reflect reimaging, resale, or unrelated tenants on the same IP. Censys notes a new SSH host key, implying possible ownership change. (https://censys.com/blog/npp-infra)
Likelihood: ~70% — This is likely because multiple independent sources describe selective targeting and a hosting‑provider compromise, which implies controlled, time‑bounded exposure rather than broad, long‑lived infrastructure. The Notepad++ incident update, Wiz summary, TechCrunch reporting, and Kaspersky rotation narrative all align with the observed service churn. Caveat: service churn alone does not prove a single operator; reimaging, resale, or unrelated tenants can create the same pattern, which keeps confidence below high. (https://notepad-plus-plus.org/news/hijacked-incident-info-update/) (https://threats.wiz.io/all-incidents/supply-chain-hijacking-of-notepad-updates-via-hosting-provider-compromise) (https://techcrunch.com/2026/02/02/notepad-says-chinese-government-hackers-hijacked-its-software-updates-for-months/) (https://www.kaspersky.com/about/press-releases/kaspersky-great-uncovers-hidden-attack-chains-in-notepad-supply-chain-compromise)

2. **TLS certificate reuse as a pivot strategy**
The Chrysalis C2 certificate for api.skycloudcenter[.]com appears on 61[.]4.102.97 and later on 160[.]250.93.48. Censys also highlights a Cobalt Strike‑like TLS certificate reused across multiple hosts, enabling infrastructure pivots. These claims are supported by Censys host history and certificate reuse evidence. (https://censys.com/blog/npp-infra)  
Why this matters: TLS reuse often reflects operator convenience or cost savings and can reveal linkage across hosts.
Challenge/Caveat: TLS certificate reuse is suggestive, not definitive. The Censys Cobalt Strike methodology article explicitly warns that certificate characteristics can be suspicious but are not proof without confirmed beacon configuration. (https://censys.com/blog/using-cobalt-strike-to-find-more-cobalt-strike)
Likelihood: ~75% — This is likely because Rapid7 confirms the C2 domain and its resolution to a specific host, while Censys shows certificate reuse across multiple hosts. That combination is a strong linkage signal consistent with deliberate pivoting. Caveat: TLS reuse is suggestive, not definitive; shared templates or reuse by other operators can produce the same artifact. (https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/) (https://censys.com/blog/npp-infra)

3. **Short exposure windows and non‑standard ports**
Several services appear for days or weeks and then disappear, including HTTPS on port 8082 and RDP (remote desktop protocol) on port 5633. This suggests the operator exposes infrastructure briefly, then moves or shuts it down. The timeline evidence is explicit in the host history sections. (https://censys.com/blog/npp-infra)  
Why this matters: short exposure windows reduce detection risk and make infrastructure harder to track. Trade‑off: shorter uptime reduces C2 availability and requires more rotation.
Challenge/Caveat: Internet scanning gaps can create the appearance of short‑lived services. The Censys report is based on scan data and explicitly states it is not enumerating all infrastructure, which limits completeness. (https://censys.com/blog/npp-infra)
Likelihood: ~65% — This is likely because Kaspersky reports monthly infrastructure and delivery overhauls, which directly supports short‑lived assets and rotation consistent with Censys timelines. Caveat: scan gaps can create false short‑lived windows; without continuous telemetry, duration remains uncertain. (https://www.kaspersky.com/about/press-releases/kaspersky-great-uncovers-hidden-attack-chains-in-notepad-supply-chain-compromise)

4. **Staging to C2 progression on the same host**
The host 59[.]110.7.32 begins as an open directory with small binaries and later presents Cobalt Strike listeners, indicating a shift from staging payloads to active C2. Staging = hosting payloads or loaders before switching to C2 services. The Censys timeline captures that progression from open directory to Cobalt Strike services. (https://censys.com/blog/npp-infra)  
Challenge/Caveat: The shift from open directory to Cobalt Strike on the same host may represent a different operator using the same host later. The report does not prove continuous ownership. (https://censys.com/blog/npp-infra)
Likelihood: ~60% — This is moderately likely because Rapid7 confirms C2 configuration and Kaspersky and F5 describe early‑chain behaviors consistent with an update‑chain staging phase leading to C2 activity. Caveat: the data does not prove continuous ownership of the host; a different operator could have reused the same host, which limits confidence. (https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/) (https://securelist.com/notepad-supply-chain-attack/118708/) (https://community.f5.com/kb/security-insights/f5-threat-report---december-17th-2025/344787)

### Details on OSINT entries That Sustains Or Challenge The Behavioral Patterns above
These sources are grouped to show what supports observed infrastructure behavior versus what bounds or challenges it.
Support ≠ proof; each source only increases or decreases likelihood.

Each entry includes what it adds and what it supports or challenges, in plain language.

1. <a id="osint-notepad"></a>

**Notepad++ incident update confirms hosting provider compromise and selective redirection**
The incident update says the compromise was at the hosting provider level, not the Notepad++ codebase, and that targeted users were selectively redirected to attacker‑controlled update manifests. It also describes the likely window as June through December 2, 2025, with server access lost in early September but credentials retained until early December. This supports a controlled, selective campaign model. (https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
Supports: pattern 1 and pattern 3 by reinforcing selective, time‑bounded exposure; pattern 4 by validating update‑chain abuse leading to C2.  
Challenges: it does not prove a single operator or continuous host ownership, so it bounds challenge 1 and challenge 4.

2. <a id="osint-wiz"></a>

**Wiz incident summary corroborates selective redirection and hosting provider access**
The Wiz incident summary describes a supply‑chain hijack via shared hosting infrastructure, selective redirection of update traffic for notepad-plus-plus.org, and operational discipline consistent with a targeted campaign. (https://threats.wiz.io/all-incidents/supply-chain-hijacking-of-notepad-updates-via-hosting-provider-compromise)
Supports: pattern 1 and pattern 3 by reinforcing selective use and controlled exposure.  
Challenges: does not tie activity to a single operator, so it bounds challenge 1.

3. <a id="osint-techcrunch"></a>

**TechCrunch reporting aligns on selective targeting and hosting provider compromise**
TechCrunch reports a multi‑month compromise, selective redirection of update traffic, and attribution to a China‑linked actor based on expert analyses. This is consistent with selective infrastructure exposure. (https://techcrunch.com/2026/02/02/notepad-says-chinese-government-hackers-hijacked-its-software-updates-for-months/)
Supports: pattern 1 and pattern 3 by confirming selective targeting over a bounded window.  
Challenges: attribution is secondary reporting, so it does not remove the uncertainty in challenge 1.

4. <a id="osint-rapid7"></a>

**Rapid7 confirms Chrysalis C2 details used in infrastructure pivoting**
Rapid7 documents decrypted configuration, including the C2 path structure under api.skycloudcenter.com and resolution to 61.4.102.97. This directly supports certificate‑based and host‑based pivots. (https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)
Supports: pattern 2 by confirming a concrete C2 endpoint that enables TLS and host pivots; pattern 4 by tying update chain to C2.  
Challenges: does not prove that TLS reuse equals a single operator, so it bounds challenge 2.

5. <a id="osint-securelist"></a>

**Kaspersky Securelist expands on multiple infection chains and rotating infra**
Kaspersky reports multiple execution chains between July and October 2025, with continuous rotation of C2 addresses and delivery chains. This strengthens the interpretation of short exposure windows and service churn. (https://securelist.com/notepad-supply-chain-attack/118708/)
Supports: pattern 1 and pattern 3 by independently confirming rotation and short lifetimes.  
Challenges: reduces but does not eliminate the scan‑artifact concern in challenge 3.

6. <a id="osint-kaspersky-pr"></a>

**Kaspersky press release confirms monthly overhaul of infra and delivery**
The press release states the attackers overhauled malware, C2 infrastructure, and delivery methods roughly every month between July and October 2025. This sustains churn and rotation. (https://www.kaspersky.com/about/press-releases/kaspersky-great-uncovers-hidden-attack-chains-in-notepad-supply-chain-compromise)
Supports: pattern 1 and pattern 3 by confirming churn and short exposure cycles.  
Challenges: reduces but does not eliminate the scan‑artifact concern in challenge 3.

7. <a id="osint-f5"></a>

**F5 threat report provides concrete post‑update behavior indicators**
The F5 report describes updater‑spawned unauthorized binaries, recon commands, and data uploaded to temp.sh using curl.exe, plus mitigation delivered in version 8.8.9. This supports behavioral detections and update chain mechanics. (https://community.f5.com/kb/security-insights/f5-threat-report---december-17th-2025/344787)
Supports: pattern 4 by reinforcing the update‑chain to post‑update execution path.  
Challenges: does not prove infrastructure continuity, so it bounds challenge 4.

8. <a id="osint-npp-889"></a>

**Notepad++ 8.8.9 release hardens update validation**
The archived official release notes state that version 8.8.9 validates the certificate and signature of downloaded installers, aborting updates when verification fails. This supports proactive controls. (https://archive.vn/2025.12.19-151754/https%3A/notepad-plus-plus.org/news/v889-released/)
Supports: pattern 4 by validating that the update chain was the exploited path.  
Challenges: mitigation guidance does not prove infrastructure ownership, so it bounds challenge 4.

9. <a id="osint-npp-89"></a>

**Notepad++ 8.9 release adds security error logging**
The version 8.9 release notes state that security errors during updates are logged to a specific security error log file, enabling proactive monitoring. (https://notepad-plus-plus.org/news/v89-released/)
Supports: pattern 4 by adding a direct update‑chain integrity signal.  
Challenges: does not establish continuity of operator control, so it bounds challenge 4.

10. <a id="osint-securelist-early"></a>

**Kaspersky Securelist documents early‑chain telemetry signals**
Kaspersky describes early chains where update.exe created directories under the user profile, collected user and process lists, and uploaded data to temp.sh. This supports specific post‑update behavioral indicators used in hunting. (https://securelist.com/notepad-supply-chain-attack/118708/)
Supports: pattern 4 by reinforcing the transition from update staging to C2‑adjacent activity.  
Challenges: does not prove host continuity, so it bounds challenge 4.

</div>

## Sources (URLs)
Links are provided in a code block to comply with repository output handling.

```text
https://censys.com/blog/npp-infra
https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
https://securelist.com/notepad-supply-chain-attack/118708/
https://www.kaspersky.com/about/press-releases/kaspersky-great-uncovers-hidden-attack-chains-in-notepad-supply-chain-compromise
https://threats.wiz.io/all-incidents/supply-chain-hijacking-of-notepad-updates-via-hosting-provider-compromise
https://www.theverge.com/tech/872462/notepad-plus-plus-server-hijacking
https://techcrunch.com/2026/02/02/notepad-says-chinese-government-hackers-hijacked-its-software-updates-for-months/
https://community.f5.com/kb/security-insights/f5-threat-report---december-17th-2025/344787
https://archive.vn/2025.12.19-151754/https%3A/notepad-plus-plus.org/news/v889-released/
https://notepad-plus-plus.org/news/v89-released/
```

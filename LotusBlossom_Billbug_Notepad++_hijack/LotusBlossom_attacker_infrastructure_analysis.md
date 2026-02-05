**Behavioral Patterns From The Report (Censys, February 3, 2026)**  
The Censys report is a network‑infrastructure focused analysis that pivots on scan data, certificate reuse, and service exposure timelines tied to the Notepad++ compromise. (censys.com (https://censys.com/blog/npp-infra))

1. **Reusable staging asset with service churn and certificate switching**  
The host 95[.]179.213.0 repeatedly alternates between Secure Shell only, short‑lived Hypertext Transfer Protocol or Hypertext Transfer Protocol Secure services on non‑standard ports, brief Virtual Private Network and Internet Key Exchange exposure, and then inactivity across February 2025 through January 2026. The report explicitly characterizes it as a reusable staging asset rather than a single‑purpose command and control server, based on the observed timeline and service swings. (censys.com (https://censys.com/blog/npp-infra))  

2. **Transport Layer Security certificate reuse as a pivot strategy**  
The Chrysalis command and control certificate for api.skycloudcenter[.]com appears on 61[.]4.102.97 and later on 160[.]250.93.48. The report also highlights a Cobalt Strike‑like certificate reused across multiple hosts, enabling infrastructure pivots. These claims are supported by Censys host history and certificate reuse evidence. (censys.com (https://censys.com/blog/npp-infra))  

3. **Short exposure windows and non‑standard ports**  
Several services appear for days or weeks and then disappear (for example, Hypertext Transfer Protocol Secure on port 8082, Remote Desktop Protocol on port 5633). This suggests the operator exposes infrastructure briefly, then moves or shuts it down. The timeline evidence is explicit in the host history sections. (censys.com (https://censys.com/blog/npp-infra))  

4. **Staging to command and control progression on the same host**  
The host 59[.]110.7.32 begins as an open directory with small binaries and later presents Cobalt Strike listeners, indicating a shift from staging payloads to active command and control. The Censys timeline captures that progression from open directory to Cobalt Strike services. (censys.com (https://censys.com/blog/npp-infra))  

———

**Challenges to behavioral patterns above**  
These are retained for completeness and grounded in sources that explicitly warn about limitations of certificate‑based attribution and scan visibility.

1. **Service churn is not proof of a single operator**  
Service changes can reflect reimaging, resale, or unrelated tenants on the same Internet Protocol address. The report itself notes a new Secure Shell host key, implying a possible reimage or ownership change. (censys.com (https://censys.com/blog/npp-infra))  

2. **Certificate reuse is suggestive, not definitive**  
Transport Layer Security certificate reuse is a strong linkage signal but not conclusive proof of a single actor. The Censys Cobalt Strike methodology article explicitly warns that certificate characteristics can be suspicious but are not proof without confirmed beacon configuration. (censys.com (https://censys.com/blog/using-cobalt-strike-to-find-more-cobalt-strike))  

3. **Short exposure windows can be a scanning artifact**  
Internet scanning gaps can create the appearance of short‑lived services. The Censys report is based on scan data and explicitly states it is not enumerating all infrastructure, which limits completeness. (censys.com (https://censys.com/blog/npp-infra))  

4. **Host progression could be a handoff**  
The shift from open directory to Cobalt Strike on the same host may represent a different operator using the same infrastructure later. The report does not prove continuous ownership. (censys.com (https://censys.com/blog/npp-infra))  

———

**Open Source Intelligence That Sustains Or Weakens The Patterns**  
These sources provide independent context that strengthens or bounds the infrastructure interpretation.

1. **Monthly overhaul of command and control infrastructure supports churn and short exposure windows**  
Kaspersky Global Research and Analysis Team reports the attackers “completely overhauled their malware, command‑and‑control infrastructure and delivery methods roughly every month between July and October 2025.” This directly sustains the Censys pattern of service churn and short exposure windows. (kaspersky.com (https://www.kaspersky.com/about/press-releases/kaspersky-great-uncovers-hidden-attack-chains-in-notepad-supply-chain-compromise))  

2. **Selective targeting and hosting‑provider compromise support controlled exposure**  
The official Notepad++ incident update says the compromise was at the hosting‑provider level, not the Notepad++ codebase, and that **targeted users** were **selectively redirected** to attacker‑controlled update manifests. It also describes the compromise window as **June through December 2, 2025**, with server access lost in early September but credentials retained until early December. This directly supports a controlled and selective campaign model. (notepad-plus-plus.org (https://notepad-plus-plus.org/news/hijacked-incident-info-update/))  

3. **Rapid7 confirms the Chrysalis command and control endpoint and domain usage**  
Rapid7 documents configuration decryption revealing a command and control Uniform Resource Locator under api.skycloudcenter.com, and explicitly states the domain resolved to 61.4.102.97. This directly supports the certificate‑based pivot and host association in the Censys report. (rapid7.com (https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/))  

4. **Update mechanism details and exploitation mechanics**  
Kevin Beaumont explains how the Notepad++ updater retrieves a manifest from getDownloadUrl.php, how the update download is saved and executed, and how interception can redirect the update Uniform Resource Locator. This explains the infrastructure abuse path and validates the feasibility of selective redirection described by Notepad++. (doublepulsar.com (https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9))  

5. **Notepad++ mitigation confirms update verification hardening**  
The Notepad++ version 8.8.9 release notes explicitly describe the update verification weakness and the new mitigation that validates signatures and certificates on downloaded update installers. This supports the narrative that update integrity checks were previously insufficient and were later hardened. (notepad-plus-plus.org (https://notepad-plus-plus.org/news/v889-released/))  

6. **Wiz incident summary independently matches the hosting‑provider compromise narrative**  
The local Wiz incident page describes a supply‑chain hijack through shared hosting infrastructure, with selective redirection of update traffic for notepad-plus-plus.org and a statement that the campaign was highly selective and focused on that domain. This independently corroborates the selective redirection behavior described by Notepad++. (threats.wiz.io (https://threats.wiz.io/all-incidents/supply-chain-hijacking-of-notepad-updates-via-hosting-provider-compromise))  

7. **TechCrunch independently reports selective targeting and the shared hosting compromise**  
The local TechCrunch article states that Notepad++ confirmed malicious updates delivered over several months in 2025, and that the shared hosting server was compromised and used to redirect selected users to malicious updates. It also attributes the campaign to a Chinese state‑linked actor based on expert analyses and references Rapid7’s attribution to Lotus Blossom, and it describes affected sectors. This aligns with the selective nature of the infrastructure. (techcrunch.com (https://techcrunch.com/2026/02/02/notepad-says-chinese-government-hackers-hijacked-its-software-updates-for-months/))  

8. **Censys methodology for Cobalt Strike identification**  
The Censys article on detecting Cobalt Strike explains how certificate‑based identification can be suggestive but not definitive, aligning with the caution in the report. (censys.com (https://censys.com/blog/using-cobalt-strike-to-find-more-cobalt-strike))  

———

**Bottom Line**  
Yes, there are meaningful behavioral patterns: infrastructure reuse with churn, certificate reuse for pivots, short exposure windows, and staging‑to‑command‑and‑control progression. The strongest sustaining evidence is Kaspersky’s statement about monthly overhauls of command and control infrastructure between July and October 2025, plus Rapid7’s confirmation of the Chrysalis command and control domain. The official Notepad++ incident update, the Wiz incident summary, and the TechCrunch reporting independently reinforce the selective, hosting‑provider‑level compromise and redirection model that the infrastructure patterns suggest. (kaspersky.com (https://www.kaspersky.com/about/press-releases/kaspersky-great-uncovers-hidden-attack-chains-in-notepad-supply-chain-compromise))  

———

**Likelihood (Evidence‑Weighted, With Open Source Intelligence Support In Mind)**

1. **Reusable staging asset with service churn and certificate switching**  
Likelihood: 70 percent  
Evidence base: Censys service timeline and Kaspersky monthly infrastructure overhauls. (censys.com (https://censys.com/blog/npp-infra))  

2. **Transport Layer Security certificate reuse as a pivot strategy**  
Likelihood: 75 percent  
Evidence base: Censys certificate reuse plus Rapid7 domain to host linkage. (censys.com (https://censys.com/blog/npp-infra))  

3. **Short exposure windows and non‑standard ports**  
Likelihood: 65 percent  
Evidence base: Censys time‑boxed service exposure plus Kaspersky infrastructure churn. (censys.com (https://censys.com/blog/npp-infra))  

4. **Staging to command and control progression on the same host**  
Likelihood: 60 percent  
Evidence base: Censys open directory then Cobalt Strike services on the same host, but weaker continuity proof. (censys.com (https://censys.com/blog/npp-infra))  

———

**Actionable Threat Hunting Actions (Proactive, Future‑Facing)**

External threat hunting activities

1. **Certificate‑centric infrastructure mapping**  
Build continuous scanning that flags any Internet‑facing host presenting the Chrysalis certificate and the Cobalt Strike‑like certificate fingerprints from the Censys report. Maintain a rolling graph of certificate reuse, host lifetimes, and overlapping service windows. This operationalizes the pivot strategy and gives early warning of infrastructure reactivation. (censys.com (https://censys.com/blog/npp-infra))  

2. **Service churn early‑warning watchlists**  
Create watchlists on candidate hosting providers and known geographic ranges for rapid shifts in exposed services, especially transitions from Secure Shell only to Hypertext Transfer Protocol or Hypertext Transfer Protocol Secure on non‑standard ports followed by disappearance. This targets reusable staging behavior. (censys.com (https://censys.com/blog/npp-infra))  

3. **Open directory and exploitation tooling detection**  
Continuously scan for open directories that contain small executables, numbered files, or exploitation tooling indicators associated with the report’s pivot hosts. This can reveal staging before command and control services appear. (censys.com (https://censys.com/blog/npp-infra))  

Internal threat hunting activities (proactive detection and prevention)

1. **Updater chain integrity enforcement**  
Implement proactive policy enforcement that allows Notepad++ update downloads only from official domains and known package repositories, and blocks updates that fail signature and certificate validation. This aligns directly with the Notepad++ mitigation guidance and reduces exposure to traffic redirection. (notepad-plus-plus.org (https://notepad-plus-plus.org/news/v889-released/))  

2. **Updater process network behavior baselining**  
Create detections that alert when the Notepad++ updater process initiates outbound network connections to domains other than the official Notepad++ and GitHub endpoints described by Kevin Beaumont. This gives early detection of redirection or interception attempts before compromise. (doublepulsar.com (https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9))  

3. **Unsigned or unexpected update execution controls**  
Deploy application control policies that prevent unsigned update executables from running, and explicitly block execution of unexpected update filenames such as update.exe or AutoUpdater.exe in temporary folders. This proactively blocks the abuse patterns described in open source reporting. (doublepulsar.com (https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9))  

4. **Behavior‑based command and control detection**  
Add detections for persistent outbound Hypertext Transfer Protocol Secure sessions on non‑standard ports from endpoints running Notepad++, with particular attention to endpoints that previously executed the updater. This anticipates the short‑exposure infrastructure model described by Censys and Kaspersky. (censys.com (https://censys.com/blog/npp-infra))  

5. **Process tree and integrity monitoring for updater flow**  
Continuously monitor updater process trees to verify that the updater only spawns expected installer binaries with valid signatures and expected parent‑child relationships. Alert on deviations, not just on known indicators. This creates durable detection even if infrastructure changes monthly. (doublepulsar.com (https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9))  

———

**Access Blocks And Gaps**  

- The previously blocked pages are now covered by local copies and cited above.  
- The Notepad++ incident update links to a clarification page and a Kaspersky Securelist article; those linked pages are **not present locally** and therefore **not reviewed**. If you add those local pages, I will integrate them and tighten the evidence chain.

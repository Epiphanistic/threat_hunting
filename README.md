# Threat Hunting Portfolio

This repository is a **portfolio-style collection** of threat hunting research notes and detection engineering examples. It is intended to demonstrate how I approach investigations end-to-end: defining a hypothesis, scoping data sources, mapping behaviors to MITRE ATT&CK, extracting indicators where appropriate, and translating findings into actionable detections and response guidance.

## Important Notes (Scope and Limitations)

- **Portfolio intent:** Content is curated to showcase methodology and thinking, not to represent a full enterprise detection program.
- **Partial coverage in places:** Some hunts are **intentionally incomplete** or lighter on validation/tuning due to **time and resource constraints** (e.g., limited telemetry, lack of access to production-grade datasets, or lack of ability to run full purple-team validation).
- **Sanitised and generalised:** Any environment-specific details, sensitive identifiers, or proprietary context have been removed or abstracted.
- **Not drop-in detections:** Queries and patterns are examples and typically require adaptation (field names, schemas, baselining, allowlists, thresholds, and local operational constraints).

## Audience

- **HR / Recruiters:** This is evidence of hands-on security work - structured thinking, investigative depth, and detection-focused deliverables.
- **Security engineers / SOC / DFIR:** You should find hypothesis-driven hunts, practical detection logic, and clear notes on what telemetry is required and how to validate or tune.

## Repository Layout

Each hunt folder generally aims to include:

- **Executive summary** (risk and why it matters)
- **Hypothesis** (what we expect to find and why)
- **Scope** (systems/identities/time windows)
- **Data sources** (logs/telemetry assumptions)
- **Detection ideas / queries** (SIEM-oriented, platform-agnostic where possible)
- **MITRE ATT&CK mapping** (tactics/techniques and rationale)
- **Validation / tuning notes** (when available)

## Hunts Index (High-Level)

| Hunt / Topic | What it covers | Typical outcomes |
|---|---|---|
| [`RMM-ScreenConnect`](RMM-ScreenConnect) | Abuse or suspicious usage patterns of ConnectWise ScreenConnect (remote access/support tooling), including provenance and operational indicators | Triage guidance, suspicious relay/host patterns, detection logic, and investigation pivots |
| [`General_ServicePrincipal_Impersonation`](General_ServicePrincipal_Impersonation) | Behavioral hunting for suspicious service principal usage (cloud identity abuse patterns, anomalous auth/permission usage) | Query patterns for hunting, baselining concepts, and detection candidates |
| [`AppSuite_PDF_Editor_Backdoor`](AppSuite_PDF_Editor_Backdoor) | OSINT-to-detection translation for a suspected malicious "PDF Editor"/updater behavior | Indicators, behaviors, and potential detection pivots (process/network/persistence) |
| [`RedDirection_Browser_Extensions`](RedDirection_Browser_Extensions) | Malicious or abused browser extensions / redirection chains and their operational footprint | Investigative pivots and detection ideas focused on extension abuse and redirect behaviors |
| [`SharePoint_ToolShell_CVE-2025-53770`](SharePoint_ToolShell_CVE-2025-53770) | Hunt notes related to ToolShell/SharePoint exploitation paths and observable post-exploitation behaviors | Threat-led pivots, suspected artifacts, and detection opportunities |
| [`Plague_PAM_Backdoor`](Plague_PAM_Backdoor) | Plague PAM backdoor behavior on Linux, authentication bypass, and persistence | Investigation pivots, IOCs, and detection ideas tied to PAM tampering and SSH access |
| [`SilkTyphoon_UNC5221`](SilkTyphoon_UNC5221) | Behavioral hunt for Silk Typhoon / UNC5221 tradecraft (cloud-fronted C2, vCenter/ESXi abuse) | DNS/tunnel pivots, auth anomalies, and vCenter investigation leads |
| [`P2P_Policy_Violation`](P2P_Policy_Violation) | Policy-driven hunt for P2P/proxyware usage, high-risk examples, and broader in-scope tooling | Endpoint inventory, DNS pivots, and remediation targets |
| [`OAST_Domains`](OAST_Domains) | OAST callback and public-tunnel domain hunting with high-entropy DNS pivots | OAST signal inventory, tunnel exposure review, and testing validation |
| [`HazyBeacon_LambdaURL_C2`](HazyBeacon_LambdaURL_C2) | Hunt for AWS Lambda URL abuse as covert C2 (HazyBeacon/CL-STA-1020) | Non-browser DNS to lambda-url.on.aws and correlated detections |
| [`Notepad_Plus_Plus_Hijacked`](Notepad_Plus_Plus_Hijacked) | WinGUp updater hijack exposure and post-update behavioral hunting | Exposure inventory, suspicious installer chains, and triage guidance |

> Note: Folder contents may vary based on what telemetry was available and whether the hunt was performed as incident-led, OSINT-led, or proactive coverage work.

## How to Use This Repo

1. Start with a hunt folder that matches the threat theme you care about (RMM abuse, identity misuse, exploitation, etc.).
2. Read the **hypothesis** and **data source assumptions** first.
3. Use the **queries/detection notes** as starting points, then adapt:
   - Normalize field names to your SIEM schema
   - Add allowlists for known-good admin tooling and service accounts
   - Tune thresholds against your environment's baseline
4. Validate against:
   - Known benign admin workflows
   - Known simulated adversary behaviors (if you can run controlled tests)

## Tooling and Approach

I generally optimize for:

- **Behavior-first detections** (reduce reliance on brittle IOCs)
- **MITRE-aligned documentation** (communicates intent and coverage)
- **Operational outcomes** (triage steps, pivots, and response actions)
- **Repeatability** (templates, query patterns, and structured notes)

## Disclaimer

This repository is provided "as is" for portfolio demonstration. No guarantees are made regarding completeness, correctness in every environment, or fitness for production without review and adaptation.

## Author

Dan Maslinca Prisecaru  
Senior Security Analyst / Detection Engineering / Threat Hunting  
Any feedback is welcomed and appreciated: [LinkedIn](https://www.linkedin.com/in/dan-maslinca-34846411/)

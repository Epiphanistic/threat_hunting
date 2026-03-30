# Trivy Ecosystem Supply Chain Compromise Hunt
Additional context: `Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md`

## Executive Summary
This hunt is scoped to the **March 19, 2026 second compromise of the Trivy ecosystem**. The priority is to identify workflows, runners, and container environments that consumed compromised Trivy components and then determine whether the known credential-theft sequence occurred.

The strongest confirmation chain is straightforward: use of compromised `aquasecurity/trivy-action` tags, compromised `aquasecurity/setup-trivy`, or malicious `trivy v0.69.4`; pre-scan shell or Python execution; process discovery against `Runner.Worker`; reads of `/proc/<pid>/environ`, `/proc/<pid>/maps`, or `/proc/<pid>/mem`; outbound traffic to `scan.aquasecurtiy.org`; and fallback GitHub activity involving `tpcp-docs`.

Docker consumers of `0.69.4`, `0.69.5`, `0.69.6`, and `latest` require a separate but related scoping track. OpenVSX and CanisterWorm remain relevant context, but they are not the primary hunt population for this report. Socket's analytic reporting places the mutable-tag blast radius at over `10,000` workflow files, which supports broad workflow scoping even before victim-level confirmation is complete.

In practice, the hunt should run in three passes: scope affected workflows and images first, validate the runner-theft sequence second, and contain or rotate only after the evidence is tied to a specific workflow, host, or token.

## Objective
- Build a scoped case list of March 19 workflow runs, runners, and build systems that resolved compromised `aquasecurity/trivy-action`, `aquasecurity/setup-trivy`, or `trivy v0.69.4`.
- Confirm whether each scoped workflow executed malicious pre-scan logic before normal Trivy scan behavior.
- Validate whether runner processes were targeted for secret extraction through `/proc` access.
- Identify outbound communications to attacker-linked infrastructure and fallback GitHub activity.
- Build a separate Docker case list for systems that pulled or ran malicious Docker tags and digests.
- Validate CanisterWorm follow-on only where upstream token theft could plausibly have exposed npm publisher credentials.
- Produce a working case table that records repository or host, affected artifact, evidence collected, analyst assessment, and required response action.

## Attack Path (Likely Mechanics)
1. Earlier GitHub Actions exploitation and incomplete containment from the late-February Trivy incident likely left the attacker with retained access.
2. On **2026-03-19**, the attacker force-updated mutable `trivy-action` tags, compromised `setup-trivy`, and published malicious `trivy v0.69.4`.
3. The malicious logic executed before the legitimate scan, allowing many workflows to complete and appear normal. CrowdStrike and Socket technical reporting place the malicious block at approximately `105` lines ahead of the normal action entry point.
4. The payload enumerated runner processes, targeted `Runner.Worker`, and accessed `/proc/<pid>/environ`, `/proc/<pid>/maps`, and `/proc/<pid>/mem` to recover secrets and credential material.
5. Collected data was staged, encrypted, and exfiltrated to `scan.aquasecurtiy.org`. Technical reporting also describes AES session-key use with RSA wrapping and broader filesystem collection on self-hosted runners.
6. When primary exfiltration failed, reporting describes fallback GitHub activity involving `tpcp-docs`.

Related follow-on activity is handled separately in this report. Docker Hub abuse and CanisterWorm propagation remain linked to the March 19 compromise, but they are not part of the primary attack path above.

## Hypothesis
If a workflow, runner, or container environment consumed compromised March 19 Trivy artifacts, the strongest confirmation chain should show affected action, tag, or image resolution followed by unexpected pre-scan shell or Python execution, discovery of `Runner.Worker` or related runner processes, reads of `/proc/<pid>/environ`, `/proc/<pid>/maps`, or `/proc/<pid>/mem`, outbound HTTPS to `scan.aquasecurtiy.org`, and, in fallback cases, unauthorized GitHub activity tied to `tpcp-docs`.

Docker-only cases should be handled as a separate follow-on track and may show malicious image pulls or suspicious runtime exposure without the full GitHub Actions sequence. CanisterWorm signals such as `pgmon.service` or ICP polling should also be treated as downstream follow-on evidence, not as proof that the primary March 19 runner-theft chain occurred on the same system.

## Blast Radius
- **Primary incident**: GitHub Actions and CI/CD consumers of mutable `aquasecurity/trivy-action` tags, compromised `aquasecurity/setup-trivy` tags, and direct consumers of `trivy v0.69.4`.
- **Scale note**: Socket's analytic reporting places the affected mutable-tag universe at over `10,000` workflow files.
- **Docker follow-on**: Docker Hub consumers who pulled `0.69.4`, `0.69.5`, `0.69.6`, or `latest` between **2026-03-19 18:24 UTC** and **2026-03-23 01:36 UTC**. Aqua states `0.69.5` and `0.69.6` were pushed with separately compromised Docker Hub credentials and had no corresponding GitHub release history.
- **OpenVSX earlier cluster**: official advisory and NVD scope is `1.8.12`; Socket extends the suspected malicious scope to `1.8.13`.
- **CanisterWorm downstream cluster**: npm publishers and developer hosts exposed after upstream token theft.
- **Tag count disagreement**: Socket reports `75 of 76` affected `trivy-action` tags; Aqua, CrowdStrike, and StepSecurity report `76 of 77`. For scoping purposes, treat all mutable `trivy-action` tags before `0.35.0` as suspect.

## Scope
- In scope: GitHub Actions jobs, CI/CD pipelines, self-hosted runners, and build environments that used `aquasecurity/trivy-action`, `aquasecurity/setup-trivy`, or `trivy` during the March 19 compromise window. Include older `trivy-action` SHA pins before `2025-04-09` where those workflows could still have transitively resolved malicious `setup-trivy` during its exposure window.
- In scope: Docker environments that pulled or ran digests associated with `0.69.4`, `0.69.5`, `0.69.6`, or `latest`, especially where containers had access to mounted secrets or the Docker socket.
- Relevant public exposure windows:
  - `trivy-action`: about 12 hours.
  - `setup-trivy`: about 4 hours.
  - `trivy v0.69.4`: about 3 hours.
  - Docker Hub tags: **2026-03-19 18:24 UTC** to **2026-03-23 01:36 UTC**.
- Safe-version note: treat `setup-trivy 0.2.6` as the restored safe tag after remediation, not as evidence that every `0.2.6` resolution during the March 19 window was clean.
- Docker scoping note: Docker states Docker infrastructure, unrelated Docker Hub images, and Docker Hardened Images were not affected.
- Docker scoping note: secondary reporting warns that cached or mirrored artifacts may have remained available after removal from the primary distribution path.
- Priority pivots: `scan.aquasecurtiy.org`, `45.148.10.212`, `/proc/<pid>/mem`, `tpcp-docs`, `~/.config/systemd/user/pgmon.service`, `~/.local/share/pgmon/`, `/tmp/pglog`, and `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`.
- Out of scope as primary narratives: `hackerbot-claw`, OpenVSX, and `Shai-Hulud 2.0`. Use them only for context or follow-on assessment.

## Hunting Telemetry
- GitHub Actions workflow logs and audit logs.
- Runner process, command-line, and file-access telemetry.
- DNS, proxy, firewall, and raw network telemetry.
- Container runtime, registry pull, and image cache telemetry.
- GitHub repository, release, and token-use audit events.
- npm package installation and publication telemetry where downstream propagation is suspected.
- StepSecurity evidence-page exemplars for anomalous `curl` behavior to `scan.aquasecurtiy.org` and `Malicious Setup-Trivy` detections.

## MITRE ATT&CK Mapping
### Initial Access
- T1195.001 - Compromise Software Supply Chain - The primary incident relied on malicious changes to trusted Trivy distribution channels, including mutable `trivy-action` tags, compromised `setup-trivy`, and malicious `trivy v0.69.4`. HIGH_ROI
Tactic: Initial Access
Procedure: Identify use of affected Trivy references during the exposure windows and map those events to runners, repositories, or container environments.
Hunt action: Search workflow, artifact, and image-consumption logs for affected Trivy references.
Expected signal: Affected references followed by pre-scan execution, runner-memory access, or suspicious outbound network activity.

### Execution
- T1059.006 - Command and Scripting Interpreter: Python - Technical reporting describes pre-scan Python execution used to steal runner secrets and stage collected data. HIGH_ROI
Tactic: Execution
Procedure: Hunt for shell-to-Python execution chained from Trivy setup or scan steps.
Hunt action: Search process trees for unexpected Python or decoded shell execution before normal scan output.
Expected signal: Shell or Python execution from a Trivy workflow step that is not part of normal scanning behavior.

### Discovery
- T1057 - Process Discovery - The payload enumerated `Runner.Worker`, `Runner.Listener`, `runsvc`, and `run.sh` before attempting secret extraction. IOC
Tactic: Discovery
Procedure: Review runner process and command-line activity for enumeration of runner components.
Hunt action: Search for runner process discovery immediately before `/proc` access or outbound traffic.
Expected signal: Process discovery against GitHub runner components within the same execution chain as secret-access behavior.

### Credential Access
- T1003.007 - OS Credential Dumping: Proc Filesystem - The clearest behavior in the March 19 incident is access to `/proc/<pid>/environ`, `/proc/<pid>/maps`, and `/proc/<pid>/mem` for runner-secret recovery. IOC HIGH_ROI
Tactic: Credential Access
Procedure: Inspect Linux runner telemetry for file access to procfs targets by Trivy-related processes.
Hunt action: Pivot on access to `/proc/*/environ`, `/proc/*/maps`, or `/proc/*/mem`, especially where the target process is `Runner.Worker`.
Expected signal: Procfs access against runner processes followed by staging or outbound transfer activity.

- T1552 - Unsecured Credentials - Reporting indicates theft of runner secrets, cloud credentials, SSH material, Kubernetes tokens, registry credentials, and other environment-resident values available to the affected execution context. HIGH_ROI
Tactic: Credential Access
Procedure: Review access to secret-bearing files, environment variables, and credential stores during affected runs.
Hunt action: Search for reads of credential material followed by archive, encryption, or transfer behavior.
Expected signal: Secret-access activity aligned to affected Trivy references and suspicious outbound traffic.

### Persistence
- T1098 - Account Manipulation - Fallback exfiltration used victim GitHub permissions to create or write to `tpcp-docs`. IOC
Tactic: Persistence
Procedure: Audit GitHub activity tied to identities or tokens used during affected workflows.
Hunt action: Search for unexpected `tpcp-docs` repository creation, release creation, or asset uploads.
Expected signal: Unauthorized GitHub write activity tied to the same identities used by affected runs.

- T1543.002 - Create or Modify System Process: Systemd Service - CanisterWorm used `~/.config/systemd/user/pgmon.service` for persistence. IOC
Tactic: Persistence
Procedure: Use this mapping only when investigating possible downstream npm propagation.
Hunt action: Search for creation or modification of `pgmon.service` and related files under `~/.local/share/pgmon/`.
Expected signal: User-level systemd persistence appearing after suspicious npm package installation.

### Command and Control
- T1071.001 - Application Layer Protocol: Web Protocols - The primary network pivot is outbound HTTPS to `scan.aquasecurtiy.org`. Analytic reporting also links the activity to `45.148.10.212`. IOC HIGH_ROI
Tactic: Command and Control
Procedure: Review DNS and web traffic from runners, containers, and developer systems for attacker-linked infrastructure.
Hunt action: Search for outbound connections to `scan.aquasecurtiy.org`, `45.148.10.212`, and, for CanisterWorm scoping, `*.raw.icp0.io`.
Expected signal: Outbound HTTPS from affected execution contexts to attacker-linked infrastructure during or shortly after Trivy execution.

- T1105 - Ingress Tool Transfer - The downstream CanisterWorm implant polled an ICP canister and downloaded a second-stage payload to `/tmp/pglog`. IOC
Tactic: Command and Control
Procedure: Apply this mapping only where suspicious npm `postinstall` behavior or `pgmon` persistence is present.
Hunt action: Search for Python-initiated network activity to `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` followed by short-lived payload staging.
Expected signal: ICP polling followed by temporary payload retrieval and execution.

### Exfiltration
- T1041 - Exfiltration Over C2 Channel - Collected data was exfiltrated to `scan.aquasecurtiy.org`, sometimes after local staging or archive creation such as `tpcp.tar.gz`. IOC HIGH_ROI
Tactic: Exfiltration
Procedure: Review network telemetry for upload behavior to the typosquatted domain.
Hunt action: Search for HTTP POST or upload patterns to `scan.aquasecurtiy.org`.
Expected signal: Outbound transfers from runners or containers that had just resolved affected Trivy components.

- T1567.002 - Exfiltration to Cloud Storage - Fallback exfiltration used GitHub repository and release infrastructure associated with `tpcp-docs`.
Tactic: Exfiltration
Procedure: Review GitHub audit logs and network telemetry for anomalous release creation or asset upload behavior.
Hunt action: Search for GitHub release or asset-upload activity tied to `tpcp-docs`.
Expected signal: Unauthorized GitHub write activity linked to affected CI identities and suspicious runner behavior.

## Query Pack
Repo-aligned query priorities are in `Trivy_Ecosystem_Supply_Chain_Compromise_Logscale_queries.md`.

## Expected Outcomes
- Affected Trivy references are followed by pre-scan shell or Python execution, runner-process discovery, procfs access, and outbound traffic to `scan.aquasecurtiy.org`. This is the strongest confirmation path for the March 19 runner-theft chain.
- GitHub audit logs show unauthorized repository creation, release activity, or uploads involving `tpcp-docs`. This materially increases confidence that fallback exfiltration occurred.
- Docker telemetry confirms use of malicious digests during the Docker exposure window, especially on hosts with mounted secrets or socket access. Those systems should be treated as separately exposed even if GitHub Actions telemetry is incomplete.
- `pgmon.service`, `~/.local/share/pgmon/`, `/tmp/pglog`, or ICP polling appear only in environments with downstream npm follow-on activity. These are follow-on indicators, not core March 19 proof points.
- A negative finding is acceptable only where there is no evidence of affected references, procfs access, suspicious outbound traffic, GitHub fallback activity, or confirmed downstream propagation.

## Triage, Validation, and Response
- Start with March 19 and immediately adjacent runs that used `aquasecurity/trivy-action`, `aquasecurity/setup-trivy`, or `trivy v0.69.4`, then record each run as `confirmed`, `suspicious`, or `negative`. Include older `trivy-action` SHA-pinned workflows where `setup-trivy` could still have been resolved during the exposure window. The first pass should answer only three questions for each run: was an affected reference used, was there evidence of pre-scan theft behavior, and was there attacker-linked outbound traffic or fallback GitHub activity.
- For each scoped run, pull the run log, runner telemetry, and network telemetry for the same time window. Confirm whether `/proc/<pid>/environ`, `/proc/<pid>/maps`, or `/proc/<pid>/mem` was accessed, whether unexpected shell or Python stages ran before normal Trivy output, and whether those actions occurred in the same process chain as the affected Trivy component.
- Review egress telemetry for `scan.aquasecurtiy.org`, `45.148.10.212`, and GitHub fallback activity involving `tpcp-docs`. If those destinations appear, capture the exact process, timestamp, destination, and transfer context in the case record rather than noting the domain alone.
- Build a separate Docker decision list: which hosts pulled affected tags, which hosts ran them, which of those had mounted secrets or socket access, and which of those hosts later used any exposed credential. Docker cases should not be marked clean until both pull history and runtime context have been reviewed.
- If downstream npm exposure is plausible, inspect for `pgmon.service`, `~/.local/share/pgmon/`, `/tmp/pglog`, and ICP polling. Also review npm account activity to determine whether any token reachable from an upstream affected runner was later used to publish or modify packages.
- Treat any host or runner with affected-reference use plus procfs access or attacker-linked outbound traffic as compromised. Preserve logs and runtime evidence first, then rotate secrets, revoke exposed tokens, and contain the affected workflow or host. For self-hosted runners, remove the runner from service until evidence collection and credential rotation are complete.
- Treat any host that pulled an affected Docker tag and had mounted secrets, cloud credentials, Kubernetes tokens, or Docker socket access as high priority. Remove the affected image, preserve pull and runtime records, rotate reachable credentials, and review whether the host later contacted any attacker-linked destination.
- When restoring workflows, replace old mutable `trivy-action` references with `0.35.0`, explicit safe SHAs, or Aqua's remediated `v`-prefixed legacy tags where an older action version is still required. Treat original pre-`0.35.0` tags as historical scoping pivots, not as safe restore targets.
- Treat OpenVSX findings as a separate incident track. Remove the extension artifact and rotate workstation-accessible secrets where `1.8.12` or analytically suspicious `1.8.13` is present. Where the extension was installed, review local AI-agent execution history and `gh` CLI activity for `posture-report-trivy`. Socket reported no public `posture-report-trivy` repositories at the time of analysis, so treat that path as suspicious but not publicly confirmed successful exfiltration.
- Use the StepSecurity run pages as supporting exemplars for runner network behavior and compromised action execution. Keep primary incident conclusions anchored to the official, vendor, and technical narrative reporting, then use the evidence pages to test whether local telemetry looks materially similar or materially different.

## False Positives and Tuning Notes
- `github.com`, `get.trivy.dev`, and `release-assets.githubusercontent.com` can appear in normal Trivy workflows. Do not elevate them without affected Trivy references, `/proc` access, `scan.aquasecurtiy.org`, or unauthorized GitHub write activity.
- Treat `45.148.10.212` as a supporting enrichment pivot, not as standalone proof of compromise. Elevate it only when it appears with affected Trivy references, `scan.aquasecurtiy.org`, runner-theft behavior, or confirmed Docker exposure.
- Python, curl, Docker, and systemd activity are common in build environments. Tune on sequence, parent-child context, timing, and co-occurrence with the affected Trivy references.
- Keep cluster boundaries intact during tuning. OpenVSX AI-agent abuse and CanisterWorm propagation are not substitute detections for the March 19 runner-theft sequence.

## Deliverables and Exit Criteria
- Deliverable: a scoped list of affected workflows, runners, container hosts, and any downstream npm publisher contexts that consumed compromised artifacts.
- Deliverable: a validation matrix showing, for each scoped case, whether affected-reference use, procfs access, outbound attacker-linked traffic, unauthorized GitHub writes, malicious Docker digests, or CanisterWorm persistence artifacts were present.
- Deliverable: a response handoff that identifies secrets and tokens to rotate, systems to contain, images to purge, and separate incident tracks to open for OpenVSX or CanisterWorm where confirmed.
- Completion criteria: the hunt is complete only when each scoped environment is either tied to confirmed malicious execution with containment underway or documented as a negative finding with no evidence of the known attack sequence.

## Static Indicators of Compromise (Supporting signals)
- Direct pivots: `scan.aquasecurtiy.org`, `45.148.10.212`, `tpcp-docs`, `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
- Artifact versions and tags: `trivy v0.69.4`, Docker tags `0.69.4`, `0.69.5`, `0.69.6`, `latest`, OpenVSX `1.8.12`, and analytically suspicious `1.8.13`
- Container digests: `27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3`, `5aaa1d7cfa9ca4649d6ffad165435c519dc836fa6e21b729a2174ad10b057d2b`, `425cd3e1a2846ac73944e891250377d2b03653e6f028833e30fc00c1abbc6d33`
- Follow-on persistence artifacts: `~/.config/systemd/user/pgmon.service`, `~/.local/share/pgmon/`, `/tmp/pglog`, `/tmp/.pg_state`

## Sources
### Primary Narrative and Vendor
- https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know
- https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise
- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
- https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know
- https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack

### Supporting Evidence Pages
- https://app.stepsecurity.io/github/actions-security-demo/compromised-packages/actions/runs/23326425755
- https://app.stepsecurity.io/github/k8gb-io/k8gb/actions/runs/23310717748?jobId=67797052912&status=anomalous&tab=network-events

### Related Analytic and Reference Sources
- https://github.com/aquasecurity/trivy-vscode-extension/security/advisories/GHSA-8mr6-gf9x-j8qg
- https://nvd.nist.gov/vuln/detail/CVE-2026-28353
- https://orca.security/resources/blog/canisterworm-npm-worm-ci-cd-breach
- https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages
- https://socket.dev/blog/trivy-docker-images-compromised
- https://socket.dev/blog/trivy-under-attack-again-github-actions-compromise
- https://socket.dev/blog/unauthorized-ai-agent-execution-code-published-to-openvsx-in-aqua-trivy-vs-code-extension
- https://www.endorlabs.com/learn/canisterworm
- https://www.stepsecurity.io/blog/canisterworm-how-a-self-propagating-npm-worm-is-spreading-backdoors-across-the-ecosystem
- https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation

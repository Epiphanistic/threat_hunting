# LiteLLM PyPI Supply Chain Compromise Hunt
Additional context: `LiteLLM_PyPI_Supply_Chain_Compromise_OSINT_report.md`

## Executive Summary
This hunt focuses on unauthorized installation, startup execution, credential access, exfiltration staging, and follow-on persistence related to malicious LiteLLM PyPI versions `1.82.7` and `1.82.8`. The primary risk is not package misuse by itself; it is credential theft from developer, CI/CD, and Kubernetes-connected environments, with optional user-level systemd persistence and cloud or cluster follow-on activity.

## Objective
- Identify endpoints, virtual environments, CI/CD jobs, and containerized workloads that installed, resolved, or executed the compromised LiteLLM releases.
- Determine whether affected systems progressed beyond package exposure into startup-hook execution, secret collection, exfiltration, persistence, or Kubernetes follow-on activity.

## Attack Path (Likely Mechanics)
1. An affected host, build runner, or virtual environment installs or resolves `litellm==1.82.7` or `litellm==1.82.8` from PyPI, directly or transitively.
2. In `1.82.8`, the malicious `litellm_init.pth` file executes automatically on Python interpreter startup and launches the payload without requiring an explicit application import. In `1.82.7`, malicious code is present in `proxy_server.py` and requires runtime reachability.
3. The payload enumerates local secrets and environment context, stages collected material under `/tmp`, encrypts the archive, and POSTs it to attacker infrastructure.
4. Where conditions permit, the malware writes `~/.config/sysmon/sysmon.py`, creates `~/.config/systemd/user/sysmon.service`, enables it via `systemctl --user`, and may also attempt Kubernetes abuse through unusual secret reads or privileged `node-setup-*` pod creation.
Variant: Environments that blocked outbound exfiltration may still show package installation, `.pth` execution, broad credential access, temporary staging artifacts, or failed persistence attempts without confirmed network success.

## Hypothesis
If an endpoint, container, or CI/CD environment installed or resolved malicious LiteLLM versions during the exposure window, the expected chain is package-install or cache events followed by Python startup-hook execution, broad secret-file access, temporary encryption or archive artifacts, outbound HTTPS to campaign infrastructure, and optionally user-level systemd persistence or Kubernetes audit anomalies in EDR, file, process, network, package, cloud, and cluster telemetry.

## Blast Radius
Blast radius is highest where LiteLLM ran in developer systems, shared build runners, AI gateways, or Kubernetes-connected automation because those environments often centralize SSH material, cloud credentials, CI/CD tokens, `.env` secrets, and cluster access. A confirmed hit should be handled as a credential compromise with potential downstream access into source control, cloud accounts, release infrastructure, and container orchestration, not merely as a local package anomaly.

## Scope
- In-scope: Linux and macOS developer endpoints, Linux CI/CD runners, containers, virtual environments, artifact caches, source-controlled dependency manifests, Kubernetes clusters, cloud workloads, and network egress telemetry covering systems that installed or ran LiteLLM on or after 2026-03-24.
- Time window: Active detection window 2026-03-24 through present for retrospective scoping; optional baseline window 14 to 30 days before 2026-03-24 for Python startup, systemd user-service, and Kubernetes secret-access frequency comparisons.
- Priority scope / Required telemetry / Out-of-scope: Shared runners, release pipelines, and systems with dense credentials take priority. Required telemetry includes package-install evidence, EDR process and file telemetry, DNS or HTTP egress, and Kubernetes audit logs where applicable. Windows registry telemetry remains out of scope for the known Linux-centric persistence pattern unless local environment-specific variants emerge.

## Hunting Telemetry
- EDR process telemetry for `python`, `pip`, `uv`, `poetry`, shell children, `openssl`, `curl`, and `systemctl --user`.
- EDR file telemetry for `site-packages` changes, `litellm_init.pth`, `proxy_server.py`, `/tmp/tpcp.tar.gz`, `/tmp/session.key`, `/tmp/payload.enc`, `/tmp/session.key.enc`, `/tmp/.pg_state`, `/tmp/pglog`, `~/.config/sysmon/sysmon.py`, and `~/.config/systemd/user/sysmon.service`.
- EDR registry telemetry: none expected for the public Linux-focused persistence path; use this line item only to record platform non-applicability.
- DNS and network telemetry for `models.litellm.cloud`, `checkmarx.zone`, related IP-based egress, and suspicious HTTPS traffic immediately following Python startup or package-resolution events.
- Identity or cloud logs including CI/CD audit trails, cloud secret-store access logs, Kubernetes audit events for `secrets` access, pod creation events, and package provenance or artifact-repository logs where available.

## MITRE ATT&CK Mapping
### Reconnaissance
- No high-confidence public reconnaissance phase is established for victim-side execution in this incident.
  Procedure: Public reporting focuses on execution, credential access, persistence, and exfiltration after malicious package delivery.
  Hunt action: Recon mapping stays low priority where telemetry support is weak; later phases with stronger observables take precedence.

### Resource Development
- T1587.001 - Develop Capabilities: Malware - The actor operated and evolved a multi-stage payload family within the broader TeamPCP campaign.
  Procedure: Reused payload components across Trivy, KICS, and LiteLLM operations, including archive naming and infrastructure patterns.
  Hunt action: Campaign constants such as `tpcp.tar.gz`, `sysmon.service`, and related domains serve as supporting pivots when clustering related incidents.

### Initial Access
- T1195.001 - Supply Chain Compromise: Compromise Software Dependencies and Development Tools - The actor published malicious code through the legitimate LiteLLM PyPI release path.
  Procedure: Valid project releases `1.82.7` and `1.82.8` were uploaded to PyPI with malicious content.
  Hunt action: Package-install logs, artifact-repository records, lockfiles, CI dependency resolution events, and wheel caches are the primary hunt surfaces for the affected versions.

### Execution
- T1546.018 - Event Triggered Execution: Python Startup Hooks - Version `1.82.8` introduced a malicious `.pth` file that executed on Python startup.
  Procedure: `litellm_init.pth` in `site-packages` triggers when Python starts, including non-application interpreter launches.
  Hunt action: Creation of `.pth` files in Python environments followed by immediate or repeated Python execution is the primary execution pivot, especially where no benign startup-hook baseline exists.
- T1059.006 - Command and Scripting Interpreter: Python - The payload uses Python execution chains and spawns additional child processes.
  Procedure: Obfuscated Python launches subsequent stages and may create noisy child-process recursion because of the `.pth` execution model.
  Hunt action: Python parent-child recursion, suspicious `python -c` execution, and Python processes quickly followed by `openssl`, `curl`, or shell activity are the core execution indicators.

### Persistence
- T1543.002 - Create or Modify System Process: Systemd Service - The malware installs a user-level systemd service named `sysmon.service`.
  Procedure: It writes `~/.config/systemd/user/sysmon.service` and enables it through `systemctl --user`.
  Hunt action: New user-level service units, especially disguised telemetry-style names, and process chains containing `systemctl --user daemon-reload` plus `enable --now` are the key persistence signals.

### Privilege Escalation
- T1611 - Escape to Host - Public reporting associates follow-on Kubernetes activity with privileged pods and host access patterns.
  Procedure: Kubernetes propagation attempts may rely on privileged workloads with host-mount or node-level setup behavior.
  Hunt action: Kubernetes audit logs should be reviewed for privileged pod specifications, hostPath mounts, `privileged: true`, and pod names matching `node-setup-*`.

### Defense Evasion
- T1027 - Obfuscated Files or Information - Public analysis describes multi-layer base64-obfuscated Python payload components.
  Procedure: Malicious code is embedded and decoded at runtime rather than exposed as plain source logic.
  Hunt action: Unusually long base64 strings in Python process command lines, decoded-to-temp-file flows, or Python plus OpenSSL combinations immediately after package execution are the strongest defense-evasion pivots.
- T1036 - Masquerading - The persistence service is presented as a benign telemetry component.
  Procedure: `sysmon.service` uses the description `System Telemetry Service` despite being attacker persistence.
  Hunt action: Newly created user services with benign operational wording that point to hidden home-directory script paths are the strongest masquerading indicators.

### Credential Access
- T1552.001 - Unsecured Credentials: Credentials In Files - The payload targets `.env`, cloud config files, Git credentials, kubeconfigs, and similar secret-bearing files.
  Procedure: File collection spans developer, CI, and cloud-related paths to maximize reusable credential yield.
  Hunt action: One process tree reading an abnormal breadth of secret-bearing files across SSH, cloud, Git, Kubernetes, shell-history, and application configuration locations is the primary credential-access signal.
- T1552.004 - Unsecured Credentials: Private Keys - SSH private keys are explicitly targeted.
  Procedure: Collection includes private-key material from user home directories.
  Hunt action: Python or short-lived shell children reading `~/.ssh/` immediately after package install, interpreter startup, or temp-artifact creation are the key private-key collection signals.

### Discovery
- T1083 - File and Directory Discovery - The malware enumerates directories and files to find secrets.
  Procedure: It inspects multiple credential-rich locations across local and cloud-integrated environments.
  Hunt action: Recursive directory access or rapid stat/open activity across secret-bearing paths by a single process tree is the strongest file-discovery signal.
- T1082 - System Information Discovery - Public reporting describes collection of local environment context.
  Procedure: Host and execution metadata are gathered to support operator awareness and follow-on action.
  Hunt action: Grouped execution of hostname, user, route, shell, or environment collection commands near the start of suspicious Python execution is the strongest system-information signal.
- T1016 - System Network Configuration Discovery - Public reporting includes network-context collection.
  Procedure: Network and routing awareness helps stage exfiltration and later access decisions.
  Hunt action: Route or interface inspection commands launched by Python or shell children in the same sequence as credential access are the primary network-discovery pivots.

### Lateral Movement
- T1610 - Deploy Container - The actor may attempt Kubernetes follow-on deployment to extend control.
  Procedure: Public reporting highlights suspicious `node-setup-*` pod creation in `kube-system` and unusual cluster secret access.
  Hunt action: Kubernetes pod creation events for `node-setup-*`, generic setup container names, `alpine:latest`, or nonstandard provisioning activity initiated by Python-based user agents are the main lateral-movement pivots.

### Collection
- T1005 - Data from Local System - The payload collects local secrets and operational files before staging them.
  Procedure: Harvested content is aggregated from the local file system into a temporary staging set.
  Hunt action: Multi-path file reads followed by writes to `/tmp/tpcp.tar.gz`, `/tmp/payload.enc`, or related staging files are the main collection signals.

### Command and Control
- T1071.001 - Application Layer Protocol: Web Protocols - Follow-on communication uses HTTPS.
  Procedure: The malware posts exfiltrated content and performs later polling over web protocols.
  Hunt action: HTTPS sessions from Python, `curl`, or shell processes to `models.litellm.cloud`, `checkmarx.zone`, or rare destinations immediately after temp-artifact creation are the main command-and-control indicators.

### Exfiltration
- T1041 - Exfiltration Over C2 Channel - Collected data is encrypted and transmitted to attacker infrastructure.
  Procedure: The malware creates an encrypted archive and sends it using outbound HTTPS.
  Hunt action: The strongest exfiltration signal is the combination of secret-file access, `/tmp` archive or encryption artifacts, `openssl rand`, AES-related file generation, and near-term outbound web traffic.

### Impact
- No discrete destructive impact phase is publicly confirmed.
  Procedure: Public reporting supports credential theft, persistence, and propagation risk, but not a separate destructive or service-disruption objective inside victim environments.
  Hunt action: Impact behaviors stay low priority unless local evidence shows tampering or operational disruption.

## Query Pack
Kusto Query Language (KQL) queries for Microsoft Defender XDR and Microsoft Sentinel are in `LiteLLM_PyPI_Supply_Chain_Compromise_KQL_queries.md`.

## Expected Outcomes
- Confirmed inventory of hosts, runners, environments, and clusters that installed or resolved `litellm==1.82.7` or `1.82.8`.
- Findings segmented into exposure-only, execution-confirmed, exfil-suspected, persistence-confirmed, and Kubernetes-follow-on categories.
- Prioritized credential-rotation scope tied to actual secret-access evidence.
- Evidence package sufficient for IR escalation, eradication, and post-incident control improvements.

## Triage, Validation, and Response
- Triage order: package installation evidence, Python startup-hook execution, secret-file access, exfiltration staging, outbound network confirmation, persistence artifacts, then Kubernetes or cloud follow-on scope.
- High-confidence escalation criteria: compromised version install plus `litellm_init.pth`; `sysmon.service` or `sysmon.py`; `/tmp/tpcp.tar.gz` or related encryption artifacts; outbound traffic to `models.litellm.cloud` or `checkmarx.zone`; or `node-setup-*` cluster activity.
- Package-exposure validation: lockfiles, `pip show`, `uv` cache inspection, CI logs, artifact repository pulls, and wheel caches.
- Execution validation: EDR process trees showing Python startup followed by shell, `curl`, `openssl`, or repeated child-Python invocation patterns.
- Artifact collection: relevant virtual environments, wheel files, package caches, shell history, EDR timeline exports, suspicious temp files, and the full contents and metadata of `~/.config/systemd/user/sysmon.service` and `~/.config/sysmon/sysmon.py`.
- Kubernetes collection: audit logs covering secret reads, pod creation, admission-controller data, and service-account usage around the exposure window.
- Evidence preservation before package cleanup or service removal where organizational policy allows.
- Immediate containment: isolate confirmed hosts or runners, disable suspicious user-level services, revoke exposed tokens, block campaign domains if still unresolved, and prevent further package installation from stale caches.
- Credential and token controls should emphasize SSH keys, source-control credentials, cloud provider keys, Kubernetes service accounts, AI provider API keys, CI/CD secrets, and any secrets present in `.env` files on impacted systems.

## False Positives and Tuning Notes
- Some Python environments legitimately use `.pth` files for bootstrap behavior; noise drops by focusing on new or rare `.pth` files associated with LiteLLM, unusual child-process fan-out, or adjacent secret-file access.
- User-level systemd services can be legitimate in developer workstations; noise drops by focusing on new services under hidden home-directory paths, telemetry-like service descriptions, or paths matching `~/.config/sysmon/`.
- Cloudflare tunnels, Python web requests, and Kubernetes secret access may be benign in some environments; correlation with compromised package versions, temp-file staging, and anomalous timing remains more reliable than any single signal.
- Temp-file names such as `/tmp/pglog` or `.pg_state` may collide with unrelated local behavior; supporting evidence from Python process ancestry, suspicious network egress, or package exposure remains necessary.

## Deliverables and Exit Criteria
- Inventory of all affected hosts, CI runners, images, caches, and clusters.
- Timeline of package install, execution, exfiltration, persistence, and containment actions.
- Findings report distinguishing confirmed, probable, and unconfirmed follow-on activity.
- Exit criteria 1: all instances of the affected versions are removed or rebuilt from trusted dependencies and caches are purged.
- Exit criteria 2: all exposed credentials in confirmed or probable scope are rotated, persistence artifacts are eradicated, and follow-on cloud or Kubernetes abuse has been investigated to closure.

## Static Indicators of Compromise (Supporting signals)
- Affected package versions: `1.82.7`, `1.82.8`
- Network pivots: `models.litellm.cloud`, `checkmarx.zone`
- Execution and persistence artifacts: `litellm_init.pth`, `~/.config/sysmon/sysmon.py`, `~/.config/systemd/user/sysmon.service`
- Staging artifacts: `/tmp/tpcp.tar.gz`, `/tmp/session.key`, `/tmp/payload.enc`, `/tmp/session.key.enc`, `/tmp/.pg_state`, `/tmp/pglog`
- Kubernetes follow-on pivots: suspicious `node-setup-*` pods, unusual `secrets` access, and privileged pod creation

## Sources
- https://docs.litellm.ai/blog/security-update-march-2026
- https://docs.litellm.ai/blog/security-townhall-updates
- https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
- https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/
- https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer
- https://www.trendmicro.com/en/research/26/c/inside-litellm-supply-chain-compromise.html
- https://digital.nhs.uk/cyber-alerts/2026/cc-4761
- https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/

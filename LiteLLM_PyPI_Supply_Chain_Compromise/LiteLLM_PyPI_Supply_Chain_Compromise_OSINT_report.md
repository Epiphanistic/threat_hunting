# LiteLLM PyPI Supply Chain Compromise OSINT Report

## Executive Summary
- On 2026-03-24, threat actors published malicious `litellm` releases `1.82.7` and `1.82.8` to PyPI through unauthorized access to the legitimate project release path. Version `1.82.8` added a Python startup hook (`litellm_init.pth`) that executed automatically on interpreter startup, materially increasing blast radius beyond explicit application imports.
- Impacted environments include developer workstations, CI/CD runners, build containers, ephemeral virtual environments, and Kubernetes-connected workloads that installed or resolved the affected versions directly or transitively.
- This is a credential-theft and persistence incident, not a routine dependency-hygiene issue. Public reporting shows collection of developer and cloud secrets, encrypted exfiltration, optional user-level systemd persistence, and follow-on Kubernetes abuse.

## Incident Overview (What is confirmed)
- LiteLLM confirmed that unauthorized PyPI publishes affected versions `1.82.7` and `1.82.8`, and that those versions were removed from PyPI after discovery.
- LiteLLM confirmed that `1.82.7` contained a malicious payload in `proxy_server.py`, while `1.82.8` contained both the malicious `proxy_server.py` payload and `litellm_init.pth`.
- LiteLLM's later townhall update stated that `v1.82.7` was pushed at 10:39 UTC on 2026-03-24, `v1.82.8` followed shortly after, and the malicious packages were live for about 40 minutes before PyPI quarantine.
- My assessment remains that the compromise fits the broader TeamPCP supply-chain campaign. Public analysis from Datadog, Snyk, Sonatype, and Trend Micro consistently links it to that campaign and assesses that stolen credentials from an earlier Trivy compromise likely enabled access to the LiteLLM release path.
- FutureSearch reported that `1.82.8` was first noticed because a transitive dependency pulled it into an MCP plugin execution context; the malicious `.pth` startup hook repeatedly re-triggered on child Python launches and effectively caused a fork-bomb condition because of a malware bug.
- Public technical analysis shows stage-two encrypted staging into `/tmp`, POST exfiltration to `https://models.litellm.cloud/`, follow-on polling to `https://checkmarx.zone/raw`, and stage-three persistence via `~/.config/sysmon/sysmon.py` and `~/.config/systemd/user/sysmon.service`.
- Public guidance also records Kubernetes follow-on activity indicators, including suspicious `node-setup-*` pods in `kube-system`, unusual secret access, and privileged pod creation patterns.

## Timeline (from public sources)
- 2026-03-24 10:39 UTC: LiteLLM `1.82.7` pushed to PyPI.
- 2026-03-24 shortly after 10:39 UTC: LiteLLM `1.82.8` published to PyPI.
- 2026-03-24 10:52 UTC: FutureSearch observed `1.82.8` on PyPI and identified the malicious `.pth` startup hook.
- 2026-03-24 12:30 UTC: FutureSearch updated public reporting to note that `1.82.7` was also compromised.
- 2026-03-24 approximately 13:38 UTC: PyPI quarantined the malicious releases.
- 2026-03-24 by 16:00 UTC: LiteLLM reported the affected packages had been deleted from PyPI.
- 2026-03-27: LiteLLM published its initial security update describing affected versions and immediate remediation expectations.
- 2026-03-28: LiteLLM published a townhall-style update with release-pipeline findings, including an unpinned Trivy dependency in CI and broad secret rotation.

## Tradecraft Evolution (Timeline-Based)
- The LiteLLM incident fits a broader TeamPCP pattern: compromise upstream tooling, steal credentials from CI or developer environments, then use those credentials to compromise downstream projects with higher-value access to developer, cloud, and AI-related secrets.
- Public reporting indicates that the campaign evolved from earlier ecosystem compromises such as Trivy into abuse of legitimate release channels for well-known packages rather than reliance on typosquatting. That shift increases trust inheritance and bypasses many standard dependency-integrity assumptions.
- In LiteLLM specifically, the actor adapted to Python execution semantics by using `.pth` startup execution in `1.82.8`. My assessment is that this is materially more dangerous than a payload that requires explicit import or direct invocation.
- Several campaign constants remained stable: staged credential harvesting, encrypted archive exfiltration using `tpcp.tar.gz`, follow-on C2/polling, and optional persistence. What changed here was delivery efficiency and likely victim reach.
- LiteLLM was not an isolated event; it was a downstream consequence of upstream release-path compromise.

## Impact and Blast Radius Analysis
### Impact (technical)
- Affected packages could execute code without an explicit `import litellm` once installed in the environment, due to the `.pth` startup hook in `1.82.8`.
- Public analysis shows harvesting of SSH keys, `.env` content, cloud credentials, Kubernetes configuration and service-account material, shell history, Git credentials, and other secrets commonly present on developer systems and CI runners.
- Exfiltration was staged through local archive and encryption artifacts such as `tpcp.tar.gz`, `session.key`, `payload.enc`, and `session.key.enc`, then transmitted via outbound HTTPS.
- Persistence could survive reboots through a user-level systemd unit named `sysmon.service`, backed by `~/.config/sysmon/sysmon.py`.
- In Kubernetes-enabled environments, the same compromise could extend to privileged pod creation and secret access, increasing scope from single-host credential theft to cluster-level exposure.

### Operational Objectives
- Steal reusable credentials and secrets from developer, CI/CD, and cloud-connected environments.
- Establish durable access through local persistence where possible.
- Reuse harvested credentials and trust relationships to move laterally into cloud, Kubernetes, source-code, and software-release infrastructure.
- Continue the broader TeamPCP objective of chaining software supply-chain compromises across ecosystems.

### Blast Radius (who is exposed)
- Organizations using LiteLLM in application development, AI gateway deployments, internal automation, MCP-related tooling, or CI/CD are in scope if they installed or resolved `1.82.7` or `1.82.8` during the exposure window.
- The highest-risk populations are developer endpoints, shared build runners, release pipelines, container build environments, and Kubernetes-connected workloads where secrets are dense and privilege is often broader than intended.
- Exposure is not limited to direct package consumers. Transitive dependency resolution, cached wheels, and ephemeral build environments significantly expand exposure.

## Detection and Validation Guidance
- Any confirmed installation or execution of `litellm==1.82.7` or `1.82.8` is a compromise candidate that requires scoping, credential review, and persistence checks.
- Priority goes to behavior-first detections over standalone IoCs: new `.pth` files in Python `site-packages`, broad secret-file access by Python or shell children, creation of `~/.config/sysmon/sysmon.py`, creation of `~/.config/systemd/user/sysmon.service`, and exfiltration staging into `/tmp` followed by outbound HTTPS.
- Validation should include whether affected hosts or CI jobs communicated with `models.litellm.cloud` or `checkmarx.zone`, but network IoCs alone are not sufficient because staging and credential access remain actionable even if outbound traffic was blocked.
- In Kubernetes, the review should cover unusual `secrets` `get` or `list` activity, privileged pod creation, and pod names matching `node-setup-*` in `kube-system`.
- Package manager caches and virtual environments matter as much as live runtime environments. FutureSearch and LiteLLM both emphasized that cached wheels and CI environments are a practical reinfection and missed-scope risk.
- Evidence preservation should happen before cleanup where feasible: wheel caches, virtual environments, shell history, process execution telemetry, EDR file timelines, and Kubernetes audit records.

## Mitigations and Hardening
- Compromised versions should be removed from all environments and pinned to a known-safe version. LiteLLM publicly recommended avoiding the affected releases and reviewing all installations or runs of those versions immediately.
- Package caches (`pip`, `uv`, container build caches, artifact caches) should be purged and environments rebuilt from trusted dependency locks.
- Credential rotation should emphasize SSH keys, cloud provider credentials, Kubernetes secrets and service-account tokens, AI API keys, Git credentials, CI/CD tokens, and any secrets stored in `.env` files on affected systems.
- Linux user-level persistence locations, especially `~/.config/systemd/user/` and `~/.config/sysmon/`, should be inspected before suspicious units are disabled or removed so evidence collection is preserved.
- In Kubernetes, the response should search for `node-setup-*` pods and privileged host-mounted containers, review secret-access logs, and revoke or rotate exposed tokens.
- Future supply-chain blast radius drops when security tools and CI dependencies are pinned, release credentials are separated from scanner or runtime contexts, secret exposure in CI is reduced, and release-path controls are strengthened.
- Additional detections for Python startup hooks and package-install-to-execution chains remain warranted. Standard integrity controls such as `pip install --require-hashes` are not sufficient when the malicious package was published with legitimate credentials and correct wheel metadata.

## Sources (OSINT)
### Primary and Vendor
- https://docs.litellm.ai/blog/security-update-march-2026
- https://docs.litellm.ai/blog/security-townhall-updates
- https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
- https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/
- https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer
- https://www.trendmicro.com/en/research/26/c/inside-litellm-supply-chain-compromise.html

### Government and CERT
- https://digital.nhs.uk/cyber-alerts/2026/cc-4761

### Additional OSINT
- https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
- https://www.csoonline.com/article/4149905/pypi-warns-developers-after-litellm-malware-found-stealing-cloud-and-ci-cd-credentials.html
- https://www.covertswarm.com/post/litellm-supply-chain-attack-pypi-backdoor

### Community and Social (Use with caution)
- No community-only references were used to establish core findings in this report.

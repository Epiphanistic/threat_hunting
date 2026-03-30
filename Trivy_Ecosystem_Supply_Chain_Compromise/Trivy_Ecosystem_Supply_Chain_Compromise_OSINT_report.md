# Trivy Ecosystem Supply Chain Compromise OSINT Report

## Executive Summary
The main incident in this package is the **March 19, 2026 second compromise of the Trivy ecosystem**. It affected mutable `aquasecurity/trivy-action` tags, `aquasecurity/setup-trivy`, and the malicious `trivy v0.69.4` release. The strongest common reporting describes pre-scan execution, theft of runner secrets from `Runner.Worker`, exfiltration to `scan.aquasecurtiy.org`, and fallback GitHub activity involving `tpcp-docs`.

This corpus also includes related but separate clusters that should stay separate in analysis and response:
- earlier `hackerbot-claw` activity that likely explains the initial foothold;
- earlier OpenVSX compromise of the Trivy VS Code extension;
- later Docker Hub tag abuse involving `0.69.5`, `0.69.6`, and `latest`;
- downstream CanisterWorm propagation using stolen npm publisher tokens.
- `Shai-Hulud 2.0` remains analogue or background material only and is not part of the Trivy incident corpus.

This report keeps those clusters separate. It does not treat them as one flat incident.

Two source disagreements matter operationally and should remain explicit:
- `trivy-action` tag count: Socket reports `75 of 76`; Aqua, CrowdStrike, and StepSecurity report `76 of 77`.
- OpenVSX affected versions: official advisory and NVD clearly cover `1.8.12`; Socket extends the suspected malicious scope to `1.8.13`.

Immediate analyst priorities are to identify affected March 19 workflows, identify Docker systems that pulled affected tags during the Docker window, review runner telemetry for the known theft sequence, rotate reachable secrets where that sequence is confirmed, and open separate scoping tracks for OpenVSX and CanisterWorm only where local evidence supports them.

## Incident Overview (What is confirmed)
On **2026-03-19**, Trivy ecosystem components were compromised a second time through mutable GitHub Action tags, `setup-trivy`, and malicious `trivy v0.69.4`. Socket places the affected mutable-tag universe at over `10,000` workflow files, which is useful context for scoping. Multiple technical sources state that the malicious logic ran before the legitimate scanner and then allowed the workflow to continue, so affected jobs could still appear normal. CrowdStrike describes the action entry point as having approximately `105` lines of malicious logic inserted ahead of the normal action code.

The core runner-theft sequence is consistent across the strongest reporting. The payload enumerated `Runner.Worker` and related processes, then accessed `/proc/<pid>/environ`, `/proc/<pid>/maps`, and `/proc/<pid>/mem` to recover secrets and other sensitive values. Technical reporting also describes broader filesystem collection on self-hosted runners and encrypted staging using an AES session key with RSA wrapping. Stolen data was sent to `scan.aquasecurtiy.org`, with fallback GitHub activity involving `tpcp-docs` when the primary path failed.

Docker exposure expanded later and should be treated as a separate follow-on branch. Docker users who pulled `0.69.4`, `0.69.5`, `0.69.6`, or `latest` during the documented window may have been exposed. Aqua states that `0.69.5` and `0.69.6` were pushed directly to Docker Hub using separately compromised Docker Hub credentials and did not have corresponding GitHub releases or tags. Docker also states that Docker infrastructure, unrelated Docker Hub images, and Docker Hardened Images were not affected. Secondary reporting notes that cached or mirrored artifacts may have remained available after the primary takedown.

The OpenVSX case is separate and earlier. Official material clearly identifies `1.8.12` as malicious. Socket extends the suspected scope to `1.8.13`, but that remains an analytic expansion rather than official consensus. Socket reports that versions through `1.8.11` matched the public repository and local build expectations, and it also describes a former employee publisher token as part of the OpenVSX context. The malicious extension attempted to invoke local AI coding agents such as Claude, Codex, Gemini, GitHub Copilot CLI, and Kiro CLI. In `1.8.13`, the logic also added a `gh`-CLI flow intended to create a repository named `posture-report-trivy`. Socket did not identify public repositories matching that name, so that path should be treated as suspicious but not publicly confirmed successful.

CanisterWorm is best understood as a downstream campaign, not the same artifact family as the March 19 GitHub Actions compromise. It reused npm publish tokens stolen from affected environments, added malicious `postinstall` logic, established `systemd --user` persistence, and polled ICP infrastructure for follow-on payloads. Public reporting highlights the `@opengov`, `@emilgroup`, and `@teale.io` namespaces, and Socket describes `135` malicious artifacts across `64+` packages.

The StepSecurity run pages are best treated as evidence pages that show the behavior in real workflows. They are useful exemplars, but they are not the primary narrative basis for incident conclusions. Official safe anchors remain `trivy-action 0.35.0`, the re-created safe `setup-trivy 0.2.6` tag, and `trivy <=0.69.3`; later guidance explicitly preserves `v0.69.2` to `v0.69.3` as the safe binary range. Analysts should still review any `setup-trivy` resolution during the March 19 exposure window because Aqua states all seven existing tags were temporarily force-pushed before `0.2.6` was restored.

## Timeline (from public sources)
- **2026-02-21 to 2026-03-02**: `hackerbot-claw` exploited GitHub Actions workflows across multiple repositories and is the strongest public explanation for the earlier Trivy foothold.
- **2026-02-27 to 2026-02-28**: malicious Trivy VS Code extension releases appeared in OpenVSX. Official scope is `1.8.12`; Socket additionally flags `1.8.13`.
- **2026-02-28**: the earlier Trivy compromise and PAT theft became the basis for later reporting on retained attacker access.
- **2026-03-01**: the first Trivy incident was publicly disclosed. Later official reporting states credential rotation was not complete or atomic.
- **2026-03-19**: the second compromise affected `trivy-action`, `setup-trivy`, and `trivy v0.69.4`.
- **2026-03-20**: safe-version guidance and technical reporting expanded; downstream CanisterWorm activity began to surface.
- **2026-03-19 18:24 UTC to 2026-03-23 01:36 UTC**: Docker identifies this as the relevant pull window for affected Docker Hub tags.
- **2026-03-22 to 2026-03-23**: new Docker findings put `0.69.5`, `0.69.6`, and `latest` at the center of follow-on scoping for container consumers, alongside the earlier `0.69.4` exposure.

## Tradecraft Evolution (Timeline-Based)
The sequence starts with earlier GitHub Actions exploitation that likely provided the initial access needed for later Trivy abuse. StepSecurity's `hackerbot-claw` reporting highlights workflow-injection techniques including `pull_request_target` abuse. That activity is best treated as enabling context rather than part of the March 19 attack path itself.

The OpenVSX compromise represents a separate distribution-channel attack against developer tooling. Its tradecraft centered on abusing local AI coding agents and permissive execution modes, with later logic intended to publish a `posture-report-trivy` repository through the local `gh` CLI. Socket also notes that the prompts were framed as a forensic or investigative task, which is relevant when reviewing local AI-agent transcript history.

The March 19 incident is the main operational case: mutable-tag abuse, malicious binary release, pre-scan execution, runner-memory theft, and covert continuation of the expected scan workflow. Wiz analytic reporting also links the broader intrusion set to Cloudflare tunnel use, including `plug-tab-protective-relay.trycloudflare.com`, but this report retains that only as contextual infrastructure rather than as a primary detection anchor.

After the March 19 window, the blast radius widened through Docker Hub and later through CanisterWorm. The Docker branch exposed malicious tags that did not line up with normal GitHub release history. The CanisterWorm branch reused stolen npm publish tokens to spread malicious packages, establish persistence with `pgmon.service`, and retrieve follow-on payloads from ICP infrastructure.

## Impact and Blast Radius Analysis
### Impact (technical)
The March 19 incident exposed secrets from CI/CD runners and any environment that trusted the affected Trivy components. The Docker branch exposed systems that pulled compromised images during the Docker window. The OpenVSX branch targeted developer workstations and local AI-agent tooling. The CanisterWorm branch targeted npm publisher ecosystems and developer hosts through malicious package installation and persistence.

### Operational Objectives
The consistent operator objective is credential theft from trusted execution environments, followed by reuse of those credentials to expand access. In practical terms:
- March 19: steal CI/CD and runner secrets.
- Docker follow-on: collect material reachable inside affected container contexts.
- OpenVSX: coerce local AI-agent tooling into broad workstation inspection and possible exfiltration.
- CanisterWorm: steal npm publish tokens and propagate through trusted package namespaces.

### Blast Radius (who is exposed)
- **March 19 primary incident**: GitHub Actions and CI/CD consumers of mutable `aquasecurity/trivy-action` tags, compromised `aquasecurity/setup-trivy` tags, and direct consumers of `trivy v0.69.4`.
- **Scale note**: Socket's analytic reporting describes over `10,000` workflow files referencing the affected mutable tags, which helps explain why broad repository and workflow scoping is necessary.
- **Docker follow-on**: Docker Hub consumers who pulled `0.69.4`, `0.69.5`, `0.69.6`, or `latest` between **2026-03-19 18:24 UTC** and **2026-03-23 01:36 UTC**.
- **OpenVSX earlier cluster**: official scope is `1.8.12`; Socket analysis extends likely impact to `1.8.13`.
- **CanisterWorm downstream cluster**: npm publishers and developer systems exposed after upstream token theft, especially where `postinstall` execution, `pgmon.service`, or ICP polling is present.
- **Commercial product boundary**: Aqua reports no indication that its commercial products were affected and describes architectural isolation from the compromised open-source environment.
- **Tag disagreement to preserve**: treat all mutable `trivy-action` tags before `0.35.0` as suspect, but keep the `75 of 76` versus `76 of 77` source split visible in reporting.

## Detection and Validation Guidance
- Start by building a scoped case list. For the March 19 branch, record every repository, workflow, run ID, runner, and build environment that resolved `trivy-action`, `setup-trivy`, or `trivy v0.69.4` during the exposure period. Do not treat older SHA pinning as automatically clean: Aqua notes that `trivy-action` commits pinned before `2025-04-09` could still transitively resolve malicious `setup-trivy` during its exposure window. For the Docker branch, build a separate list of systems that pulled `0.69.4`, `0.69.5`, `0.69.6`, or `latest` during the Docker window. Do not mix those lists.
- For each March 19 workflow case, collect the run log, runner process telemetry, file-access telemetry, and network telemetry for the full run window. The first question is whether anything executed before normal Trivy behavior. The second question is whether the run touched `Runner.Worker`, `/proc/<pid>/environ`, `/proc/<pid>/maps`, or `/proc/<pid>/mem`. The third question is whether the same run reached `scan.aquasecurtiy.org:443` or a GitHub fallback path.
- For each positive or suspicious runner case, review GitHub audit activity for fallback behavior tied to `tpcp-docs` or `tpcp-docs-*`. Specifically check for unexpected repository creation, release creation, asset upload activity, or token use from an unusual source after the affected run.
- Use the StepSecurity evidence pages as concrete exemplars, not as primary narrative sources. One shows repeated `curl` traffic to `scan.aquasecurtiy.org` from `aquasecurity/trivy-action@ab6606b...`; another shows a `Malicious Setup-Trivy` detection with outbound destinations including `scan.aquasecurtiy.org`, `github.com`, `get.trivy.dev`, and `release-assets.githubusercontent.com`. Analysts should use those examples to compare process order, destination order, and surrounding normal traffic.
- For Docker cases, collect registry pull records, runtime telemetry, and container configuration details. Separate systems into three groups: containers with no sensitive mounts, containers with mounted secrets or cloud credentials, and containers with Docker socket access. Work the last two groups first because they create the highest follow-on risk.
- For OpenVSX scoping, verify whether `1.8.12` was installed from OpenVSX. Treat `1.8.13` as a separate analytic scope expansion unless internal evidence confirms it. Where the extension was present, review local AI-agent execution history, shell history, and `gh` CLI activity for references to `posture-report-trivy`, broad file discovery, or repository creation attempts.
- For CanisterWorm scoping, validate creation of `~/.config/systemd/user/pgmon.service`, writes under `~/.local/share/pgmon/`, execution from `/tmp/pglog`, artifacts such as `/tmp/.pg_state`, `systemctl --user enable/start` activity, or polling of `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`. Also review npm account activity to determine whether publish tokens were used after the upstream CI/CD compromise window.
- Classify each scoped workflow, host, or workstation as `confirmed`, `suspicious`, or `negative`. A `confirmed` case should show affected-reference use plus theft-sequence behavior or attacker-linked network activity. A `suspicious` case should show affected-reference use with incomplete supporting telemetry. A `negative` case should show affected-reference use but no corroborating runner, Docker, OpenVSX, or CanisterWorm evidence after review.

## Mitigations and Hardening
- Pin or restore the affected Trivy components to safe versions first: `trivy-action 0.35.0`, the restored safe `setup-trivy 0.2.6` tag, and `trivy 0.69.3` or earlier safe releases identified in official guidance. Replace mutable references in workflows with known-safe versions or explicit safe commits before re-enabling those workflows. If an older `trivy-action` release is still required, use the remediated `v`-prefixed tags published by Aqua rather than the original pre-`0.35.0` mutable tags.
- For any confirmed or suspicious March 19 case, treat every secret reachable from that runner as exposed until proven otherwise. Rotate GitHub tokens, cloud credentials, registry credentials, Kubernetes tokens, SSH material, and any environment-resident secrets available to the run. If the run had publish or deployment rights, rotate those first.
- For positive March 19 cases, preserve evidence before cleanup. Retain run logs, GitHub audit logs, network telemetry, affected workflow definitions, and any runner diagnostics that show process creation, `/proc` access, or outbound destinations. Do not wipe a self-hosted runner before that evidence is collected.
- For Docker exposure, remove affected images from local caches and mirrors, inspect every host that pulled them during the Docker window, and treat hosts with mounted secrets or socket access as high priority. If the container had access to cloud credentials, Kubernetes tokens, or the Docker socket, assume follow-on credential exposure is possible and rotate accordingly.
- For OpenVSX exposure, remove the extension artifact immediately. At minimum, remove `1.8.12`. Extend to `1.8.13` if internal scoping supports the Socket assessment. After removal, review local AI-agent history, shell history, and `gh` CLI use, then rotate secrets exposed to that workstation.
- For CanisterWorm exposure, revoke npm publish tokens, inspect package publication history for unauthorized pushes, remove `pgmon` persistence, review package-install telemetry on affected developer systems, and check whether the user account can still publish into any sensitive namespace.
- Keep incident handling separated by cluster. The March 19 runner theft, Docker follow-on, OpenVSX compromise, and CanisterWorm propagation should be cross-referenced, not merged into a single flat case file. Each cluster should have its own case list, evidence record, and decision status.

## Sources (OSINT)
### Primary and Vendor
- https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- https://github.com/aquasecurity/trivy-vscode-extension/security/advisories/GHSA-8mr6-gf9x-j8qg
- https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know
- https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise
- https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know
- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
- https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack

### Government and CERT
- https://nvd.nist.gov/vuln/detail/CVE-2026-28353

### Supporting Evidence Pages
- https://app.stepsecurity.io/github/actions-security-demo/compromised-packages/actions/runs/23326425755
- https://app.stepsecurity.io/github/k8gb-io/k8gb/actions/runs/23310717748?jobId=67797052912&status=anomalous&tab=network-events

### Additional Analytic OSINT
- https://orca.security/resources/blog/canisterworm-npm-worm-ci-cd-breach
- https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages
- https://socket.dev/blog/trivy-docker-images-compromised
- https://socket.dev/blog/trivy-under-attack-again-github-actions-compromise
- https://socket.dev/blog/unauthorized-ai-agent-execution-code-published-to-openvsx-in-aqua-trivy-vs-code-extension
- https://www.endorlabs.com/learn/canisterworm
- https://www.stepsecurity.io/blog/canisterworm-how-a-self-propagating-npm-worm-is-spreading-backdoors-across-the-ecosystem
- https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation

### Community and Social (Use with caution)
- None used in this synthesis.

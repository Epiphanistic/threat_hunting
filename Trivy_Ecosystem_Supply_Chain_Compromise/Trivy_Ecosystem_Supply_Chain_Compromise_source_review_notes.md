# Trivy Ecosystem Supply Chain Compromise Source Review Notes

Generated: 2026-03-24 13:19 UTC

## Why this file exists

These notes were preserved as a supporting file for later comparison against repo revisions and derived hunt output.  
They are based on the **uploaded PDFs only** and are intentionally paraphrased. They are not a substitute for the source material.

## Core normalization warning

This corpus is **not one single incident**. It contains several related but distinct clusters. Any later output that blends them into one flat narrative without boundaries is wrong.

### Cluster map

1. **Earlier enabling context (Feb 21 - Mar 2, 2026)**  
   `hackerbot-claw` GitHub Actions exploitation campaign. This appears to explain the **initial Trivy foothold / PAT theft** used before the later March 19 activity.

2. **OpenVSX / VS Code extension compromise (Feb 27 - Feb 28, 2026)**  
   Trivy VS Code extension releases in OpenVSX (`1.8.12`, and in Socket analysis also `1.8.13`) contained malicious code that abused **local AI coding agents**.

3. **Second Trivy compromise (Mar 19, 2026)**  
   Main March incident: `trivy-action`, `setup-trivy`, `trivy v0.69.4`, later Docker images. This is the **center of gravity** of the corpus.

4. **Docker image follow-on (Mar 22 - Mar 23, 2026)**  
   Compromised Docker Hub tags `0.69.5`, `0.69.6`, and `latest`.

5. **CanisterWorm follow-on (Mar 20 - Mar 23, 2026)**  
   Follow-on npm worm campaign using tokens stolen from affected CI/CD/developer environments.

6. **Analogue / background only**  
   `Shai-Hulud 2.0` is a useful precedent for self-propagating npm worms, but it is **not a Trivy incident document**.

## Source inventory and role

| File | Pages | Cluster | Role | Notes |
|---|---:|---|---|---|
| `Trivy Under Attack Again_ Widespread GitHub Actions Tag Comp.._.pdf` | 16 | Mar 19 GitHub Actions tag hijack | Secondary/analytic | Socket view of trivy-action tag hijack scale; 10k+ workflow references; 75/76 tag count convention; notes why @0.35.0 stayed clean. |
| `From Scanner to Stealer_ Inside the trivy-action Supply Chain Compromise.pdf` | 14 | Mar 19 GitHub Actions tag hijack | Primary/technical | Best payload internals for trivy-action; multi-stage stealer, /proc memory scraping, AES+RSA packaging, dual exfil, workflow-normality camouflage. |
| `Trivy Compromised a Second Time - Malicious v0.69.4 Release, aquasecurity_setup-trivy, aquasecurity_trivy-action GitHub Actions Compromised - StepSecurity.pdf` | 40 | Mar 19 second compromise | Primary/technical+operational | Most complete public walkthrough tying earlier Feb 28 foothold to Mar 19 second compromise; durations, evidence, recovery guidance, Docker update. |
| `Trivy Compromised by _TeamPCP_ _ Wiz Blog.pdf` | 14 | Mar 19 second compromise | Primary/analytic | Connects TeamPCP activity across binaries, actions, Docker, Cloudflare tunnel, fallback tpcp-docs repo, and ICP canister; useful IOC appendix. |
| `Trivy ecosystem supply chain temporarily compromised · Advisory · aquasecurity_trivy.pdf` | 5 | Official advisory | Primary/official | Authoritative affected/safe versions; official summary; acknowledges non-atomic credential rotation and affected channels. |
| `Update_ Ongoing Investigation and Continued Remediation.pdf` | 16 | Official update | Primary/official | Official root-cause narrative, enterprise/commercial isolation statement, IR remediation posture, IOCs and community actions. |
| `Trivy Supply Chain Attack Expands to Compromised Docker Imag.._.pdf` | 9 | Docker image follow-on | Secondary/analytic | Focuses on Docker Hub 0.69.5/0.69.6/latest artifacts without matching GitHub releases; cache/mirror persistence angle. |
| `Trivy supply chain compromise_ What Docker Hub users should know _ Docker.pdf` | 7 | Docker impact | Primary/vendor-specific | Docker-specific impact window and customer guidance for Docker Hub pulls; clarifies Docker infra and DHI not impacted. |
| `Run #23310717748 · k8gb-io_k8gb _ StepSecurity.pdf` | 1 | Evidence page | Supporting evidence | Concrete StepSecurity run showing anomalous curl to scan.aquasecurtiy.org from trivy-action in a real project run. |
| `Run #23326425755 · actions-security-demo_compromised-packages _ StepSecurity.pdf` | 1 | Evidence page | Supporting evidence | Demo run page showing Malicious Setup-Trivy detection and outbound destinations. |
| `Malicious Trivy OpenVSX Extension Release · Advisory · aquasecurity_trivy-vscode-extension.pdf` | 1 | OpenVSX compromise | Primary/official | Official advisory for version 1.8.12; no patched version listed; remove artifact and rotate secrets. |
| `NVD - CVE-2026-28353.pdf` | 3 | OpenVSX compromise | Primary/reference | CVE record for compromised OpenVSX artifact; CVSS 4.0 critical, awaiting NVD analysis. |
| `Unauthorized AI Agent Execution Code Published to OpenVSX in.._.pdf` | 15 | OpenVSX compromise | Primary/technical | Best technical analysis of AI-agent abuse payload in 1.8.12/1.8.13; includes former employee publisher token context, tool execution patterns, likely limited exfil evidence. |
| `CanisterWorm_ How a Self-Propagating npm Worm Is Spreading Backdoors Across the Ecosystem - StepSecurity.pdf` | 14 | CanisterWorm follow-on | Primary/analytic | Clear continuation from Trivy compromise to npm token theft and worm propagation; highlights @opengov scope and propagation chain. |
| `CanisterWorm_ Malicious npm Packages Deploy Self-Propagating Supply Chain Worm _ Blog _ Endor Labs.pdf` | 22 | CanisterWorm follow-on | Primary/technical | Most explicit persistence and mitigation details; service path, C2 URL, token handling, many affected packages. |
| `CanisterWorm_ Trivy Breach Spreads npm Worm _ Orca Security.pdf` | 11 | CanisterWorm follow-on | Primary/analytic | Strong executive summary of cross-boundary progression from CI/CD into developer hosts and registries. |
| `CanisterWorm_ npm Publisher Compromise Deploys Backdoor Acro.._.pdf` | 10 | CanisterWorm follow-on | Primary/analytic | Good campaign growth numbers (135 artifacts/64+ packages), @emilgroup/@teale.io focus, staged evolution, ICP dead-drop explanation. |
| `hackerbot-claw_ An AI-Powered Bot Actively Exploiting GitHub Actions - Microsoft, DataDog, and CNCF Projects Hit So Far - StepSecurity.pdf` | 43 | Earlier enabling context | Context/background | Important for how the initial Trivy PAT theft happened, but not the same incident as Mar 19 second compromise. |
| `The Shai-Hulud 2.0 npm worm_ analysis, and what you need to know _ Datadog Security Labs.pdf` | 17 | Analogue/background | Context/analogue | Useful analogy for self-propagating npm worms; not Trivy-specific and should not be blended into incident facts. |


## High-confidence synthesis

### 1) What the March 19 second compromise appears to be

Across the StepSecurity, CrowdStrike, Aqua, Wiz, Docker, and Socket PDFs, the strongest common narrative is:

- A **prior compromise / incomplete containment** left the attacker with residual access after the earlier Trivy incident.
- On **March 19, 2026**, the attacker abused that access to:
  - publish a malicious **Trivy binary release** (`v0.69.4`);
  - poison **GitHub Actions** references by force-updating tags in `aquasecurity/trivy-action`;
  - compromise `aquasecurity/setup-trivy`;
  - later extend impact into **Docker Hub** and **npm**.
- The GitHub Actions payload executed **before the legitimate scanner**, then allowed the workflow to proceed normally. Multiple sources explicitly stress that workflows could appear successful even while secrets were being stolen.

### 2) Payload behavior repeatedly described across sources

The common payload themes are:

- Enumeration of GitHub Actions runner processes such as `Runner.Worker`.
- Secret extraction from runner state, including memory scraping from `/proc/<pid>/mem` on Linux GitHub-hosted runners.
- Broader filesystem harvesting on self-hosted runners.
- Targeting of:
  - CI/CD secrets
  - cloud credentials
  - SSH material
  - Kubernetes tokens
  - registry credentials
  - environment variables / `.env` style data
- Encryption of stolen data before exfiltration.
- Primary exfiltration to the typosquatted domain `scan.aquasecurtiy[.]org`.
- Fallback exfiltration using a GitHub repository named `tpcp-docs`.

### 3) Version / tag / safe-version picture that should survive comparison

This is one of the most important comparison areas.

#### Official / near-official safe-version picture

- **Trivy binary**  
  affected: `v0.69.4`  
  safe: `v0.69.3` (official advisory also mentions `v0.69.2`-`v0.69.3` in later guidance)

- **trivy-action**  
  affected: `<0.35.0` / effectively tags `0.0.1 - 0.34.2`  
  safe: `0.35.0`

- **setup-trivy**  
  affected: `<0.2.6` / effectively all earlier tags in the March event  
  safe: `0.2.6`

#### Docker Hub view

Docker and Socket together indicate:

- `0.69.4`, `0.69.5`, `0.69.6`, and `latest` matter for Docker consumers.
- `0.69.5` and `0.69.6` are particularly important because they were pushed to Docker Hub **without corresponding GitHub releases/tags**.
- Docker's customer-facing window is broader than just the original March 19 release event.

### 4) Why later output must keep the CanisterWorm story separate but linked

The CanisterWorm PDFs consistently frame the npm worm as a **downstream continuation** of the Trivy compromise, not the same event.

The common chain is:

1. Trivy CI/CD compromise steals **npm publish tokens**.
2. Those tokens are abused to republish legitimate packages with malicious code.
3. Malicious packages execute a **postinstall** hook.
4. The hook drops a **Python-based implant**.
5. Persistence is established through **user-level systemd**.
6. The implant polls an **ICP / Internet Computer** canister for follow-on payload delivery.
7. The worm then republishes compromised versions across more reachable packages/namespaces.

That linkage is important:
- **Trivy compromise** = upstream credential theft / trusted distribution abuse.
- **CanisterWorm** = downstream propagation and host persistence.

### 5) Why later output must keep the OpenVSX story separate but linked

The OpenVSX PDFs are about a **different Trivy-related compromise**, earlier in time.

The high-signal points are:

- OpenVSX releases `1.8.12` and, in Socket's analysis, also `1.8.13`, included malicious code not present in the public GitHub repository or tagged releases.
- The malicious extension attempted to invoke multiple local AI coding agents in highly permissive modes.
- The payload's intent was broad system inspection and potential exfiltration, including use of the local `gh` CLI to create a repository named `posture-report-trivy`.
- Official advisory / CVE material names **`1.8.12`** as the affected version; Socket extends this to **`1.8.13`** as well.

This means later output should treat OpenVSX as:
- a **related Trivy security incident**,  
- probably linked operationally to the broader attack pressure on Aqua/Trivy,  
- but **not the same artifact family** as the March 19 GitHub Action tag hijack.

## Key timeline notes

## Condensed sequence

- **Feb 21 - Mar 2, 2026**: `hackerbot-claw` campaign targets multiple GitHub repos.
- **Feb 27 - Feb 28, 2026**: malicious OpenVSX Trivy extension versions `1.8.12` / `1.8.13` published.
- **Feb 28, 2026**: earlier Trivy incident / PAT theft / repo takeover context.
- **Mar 1, 2026**: first incident disclosed; credential rotation performed, but later sources say rotation was **not atomic / not comprehensive**.
- **Mar 19, 2026**: second compromise hits `trivy-action`, `setup-trivy`, and `v0.69.4`.
- **Mar 20, 2026**: safe-version guidance / public analysis / official advisory activity intensifies.
- **Mar 22, 2026**: malicious Docker Hub images `0.69.5` / `0.69.6` and `latest` become central.
- **Mar 20 - Mar 23, 2026**: CanisterWorm expands through npm publisher ecosystems.

## Specific time facts worth preserving

### From official / vendor docs

- Aqua advisory:
  - `trivy-action` exposure approximately **12 hours**
  - `setup-trivy` exposure approximately **4 hours**
  - `trivy v0.69.4` exposure approximately **3 hours**
- Docker:
  - Docker Hub users who pulled affected images between **18:24 UTC on March 19, 2026** and **01:36 UTC on March 23, 2026** may have been exposed if they used the affected tags.

## High-signal indicators and artifacts

### Network / exfil / infrastructure

- `scan.aquasecurtiy[.]org`
- `45.148.10.212`
- `plug-tab-protective-relay.trycloudflare.com`
- `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`

### GitHub / repo artifacts

- fallback exfil repo: `tpcp-docs`
- public org repo pattern mentioned in Docker/Socket follow-on context: `tpcp-docs-*`
- OpenVSX AI-agent exfil repo name: `posture-report-trivy`

### Files / local persistence / output artifacts

- `~/.config/systemd/user/pgmon.service`
- `~/.local/share/pgmon/`
- `/tmp/pglog`
- `/tmp/.pg_state`
- `payload.enc`
- `session.key.enc`
- `tpcp.tar.gz`
- `REPORT.MD` (OpenVSX AI-agent prompt flow)

### Affected version anchors

- `v0.69.4`
- `v0.69.5`
- `v0.69.6`
- `latest` (Docker image angle)
- `1.8.12`
- `1.8.13`
- `0.35.0`
- `0.2.6`

### Official identifiers

- `GHSA-69fq-xp46-6x23`
- `GHSA-8mr6-gf9x-j8qg`
- `CVE-2026-28353`

## Per-cluster notes

### A. Earlier enabling context - `hackerbot-claw`

This PDF is important because it explains **how the first Trivy foothold appears to have happened**.

High-signal points:
- automated bot campaign against GitHub Actions workflows;
- 5 exploitation techniques across 7 targets;
- Trivy is listed as the highest-profile target with **full repository compromise**;
- includes `pull_request_target` abuse and other workflow-injection patterns;
- explicitly ties the Trivy PAT theft / repo takeover to the larger campaign;
- should be treated as **enabling context**, not as the March 19 incident itself.

### B. OpenVSX compromise

#### Official advisory / CVE view
- Official GHSA says affected version is `1.8.12`.
- No patched version is listed in the advisory PDF.
- Guidance is to remove the artifact and rotate secrets.
- NVD record exists as `CVE-2026-28353`, with NVD still awaiting full analysis at the time of the PDF.

#### Socket technical view
Most detailed technical observations in the corpus:
- `1.8.12` and `1.8.13` both looked malicious.
- Versions up to `1.8.11` matched the public repo / local build.
- Malicious logic ran from the extension activation path.
- It attempted to launch:
  - Claude
  - Codex
  - Gemini
  - GitHub Copilot CLI
  - Kiro CLI
- It used highly permissive execution modes.
- The prompt framed the agent as a **forensic investigator** to try to stay inside model safety boundaries while still collecting sensitive data.
- Version `1.8.13` added an explicit `gh`-CLI-based repo creation / report publishing flow (`posture-report-trivy`).
- Socket says it found **no public repos** matching `posture-report-trivy`; that suggests limited or no confirmed successful exfiltration via that path, but not guaranteed zero impact.

Important boundary:
- Later comparison output should not claim that the official advisory fully covered `1.8.13`; the official advisory PDF and NVD PDF only clearly acknowledge `1.8.12`.

### C. March 19 second compromise - main incident

#### What later output should capture cleanly
- This is the main Trivy ecosystem incident in the corpus.
- It spans:
  - malicious binary release (`v0.69.4`)
  - poisoned GitHub Action tags (`trivy-action`)
  - compromised `setup-trivy`
  - later Docker image abuse
- Workflows often still completed normally because the malicious code ran first and then allowed the real Trivy logic to execute.

#### Payload internals that appear consistently
CrowdStrike is the strongest technical source here:
- action entry point modified with about ~100 lines of malicious logic before normal action code;
- process discovery against runner components;
- memory scraping from `Runner.Worker` via `/proc/*/maps` and `/proc/*/mem`;
- filesystem credential harvesting on self-hosted paths;
- AES session key + RSA wrapping;
- packaged output like `tpcp.tar.gz`;
- exfil to typosquat C2 and fallback GitHub repo creation.

Wiz adds:
- broader Aqua account compromise context,
- Cloudflare tunnel use,
- IOC appendix,
- `tpcp-docs` fallback detail,
- attribution language around `TeamPCP`.

Aqua adds:
- official safe versions,
- official statement that the first incident's rotation was not comprehensive / not atomic,
- official assurance that commercial products were isolated from the open-source blast radius.

### D. Docker image follow-on

Socket + Docker together provide the clearest Docker story:

- affected tags: `0.69.4`, `0.69.5`, `0.69.6`, `latest`
- `0.69.5` and `0.69.6` were pushed to Docker Hub without corresponding GitHub releases
- `latest` also pointed to malicious content during the exposure window
- cached / mirrored artifacts may have persisted even after removal
- Docker explicitly says:
  - DHI / Docker Hardened Images were not affected
  - Docker infrastructure and other Docker Hub images were not affected
  - users should treat systems that pulled those images as exposed and rotate credentials

This is important: a later output that only talks about `v0.69.4` and ignores `0.69.5` / `0.69.6` / `latest` is incomplete for Docker consumers.

### E. CanisterWorm follow-on

The four CanisterWorm PDFs are strongly aligned on the campaign shape.

#### Common mechanics
- malicious npm packages run a `postinstall` hook;
- hook writes / decodes a Python implant;
- persistence through `systemd --user`;
- service name commonly `pgmon.service`;
- implant polls an ICP canister for second-stage payload URLs;
- worm steals npm tokens and republishes malicious patch versions under packages the victim can publish.

#### What each CanisterWorm source is best for

- **StepSecurity**  
  Best at linking CanisterWorm directly back to the Trivy second compromise. It emphasizes the stolen npm-token path and highlights spread into `@opengov` (`16+ packages`).

- **Endor Labs**  
  Best for host-level persistence and mitigation detail:
  - `~/.config/systemd/user/pgmon.service`
  - `/usr/bin/python3 ...`
  - `systemctl --user enable/start`
  - C2 via `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
  - advice to inspect dependency manifests, file paths, network logs, npm account activity.

- **Orca**  
  Best executive summary of the cross-boundary nature of the attack: CI/CD -> developer workstation -> package ecosystem.

- **Socket**  
  Best campaign growth framing:
  - `135` malicious artifacts
  - `64+` unique packages
  - specific namespace emphasis: `@emilgroup`, `@teale.io`
  - staged evolution from early postinstall staging to more standardized persistence and `latest` tag republishing.

Important boundary:
- These are **downstream follow-on docs**, not the core March 19 GitHub Actions attack docs.

### F. Shai-Hulud 2.0

This is **contextual only**.

Why it matters:
- provides a prior pattern for a self-propagating npm worm;
- helps frame CanisterWorm as part of a broader class of npm worm behavior;
- shows other worm design elements such as GitHub-native exfil, self-hosted runner usage, and destructive fallback behavior.

Why it should not dominate later output:
- it is **not** about Trivy;
- it is an analogy / precedent, not evidence for the Trivy case.

## Specific evidence pages

### `Run #23310717748 · k8gb-io_k8gb`
High-value because it is concrete and compact.

What it shows:
- anomalous outbound network events from `aquasecurity/trivy-action@ab6606b76e5...`
- repeated `curl` connections to `scan.aquasecurtiy.org:443`
- multiple Trivy-related steps flagged as anomalous
- real project evidence, not just theory

### `Run #23326425755 · actions-security-demo_compromised-packages`
What it shows:
- StepSecurity demo run with `Malicious Setup-Trivy` detection
- outbound destinations included:
  - `scan.aquasecurtiy.org`
  - `github.com`
  - `get.trivy.dev`
  - `release-assets.githubusercontent.com`

These evidence pages should be used in later comparison as **ground-truth exemplars**, not as narrative sources.

## Important discrepancies / edge cases to preserve

### 1) Tag count discrepancy
There is a visible count mismatch across sources:

- Socket: `75 out of 76` version tags in `trivy-action`
- CrowdStrike / Aqua / StepSecurity: `76 of 77`

Do **not** flatten this into a single unqualified fact without acknowledging source variance.  
Likely explanation: different counting conventions around total tags / clean tag / release-tag universe.

### 2) OpenVSX affected version discrepancy
- Official GHSA + NVD clearly discuss `1.8.12`.
- Socket analysis extends malicious behavior to `1.8.13`.

A strong later output should preserve that distinction instead of pretending all sources say the same thing.

### 3) First incident vs second incident
Some docs are explicitly about the **second** Trivy compromise on March 19, but they also carry context from:
- the earlier Feb 28 repo takeover / PAT theft
- the OpenVSX compromise
- the later Docker and npm follow-ons

Later output should keep cause/effect ordering clear.

### 4) Docker release interpretation
- GitHub release / source-tag timelines are not the same as Docker Hub tag timelines.
- `0.69.5` and `0.69.6` are especially important because they were visible in Docker Hub without matching GitHub release history.

### 5) CanisterWorm namespace scope
Sources emphasize different visible slices:
- `@opengov`
- `@emilgroup`
- `@teale.io`
- broader `64+` / `135 artifacts` view

Later output should treat these as **complementary slices of the same follow-on worm campaign**, not mutually exclusive contradictions.

## What strong derived hunt output should do

### It should

- separate the corpus into incident clusters;
- state the relationship between clusters;
- identify the main March 19 incident as the center of gravity;
- keep official safe versions and vendor exposure windows intact;
- extract the main IoCs and artifacts cleanly;
- preserve source disagreements instead of smoothing them away;
- avoid treating background docs as primary evidence;
- mention both CI/CD runner theft and downstream host persistence / package propagation.

### It should not

- merge `hackerbot-claw`, OpenVSX, March 19 action hijack, Docker follow-on, and CanisterWorm into one undifferentiated story;
- present `Shai-Hulud 2.0` as if it were part of the Trivy incident;
- treat `1.8.13` as officially acknowledged in the GHSA/NVD unless explicitly marked as coming from Socket analysis;
- ignore Docker-specific `latest` / `0.69.5` / `0.69.6` exposure;
- ignore the official note that earlier credential rotation was incomplete;
- ignore that some workflows appeared normal even while the payload ran.

## Comparison checklist for later revisions

Use this checklist when comparing later derived hunt output to these notes.

### Structure
- Does it split the corpus into the right clusters?
- Does it clearly label primary vs supporting vs contextual sources?

### Accuracy
- Does it preserve safe versions and affected versions correctly?
- Does it keep Docker Hub facts separate from GitHub release facts?
- Does it keep OpenVSX version disagreement explicit?

### Technical depth
- Does it capture:
  - mutable tag hijack / force-push angle
  - runner-memory scraping
  - fallback exfil repo
  - Docker tag drift
  - `postinstall` + `systemd --user` persistence
  - ICP canister dead-drop
  - AI-agent abuse in VS Code extension

### Fidelity to corpus
- Does it use the StepSecurity run screenshots as evidence pages rather than main narrative sources?
- Does it avoid importing unsupported facts from outside the uploaded PDFs?

### Noise control
- Does it avoid overweighting site chrome, sidebars, and repeated cross-links?
- Does it avoid turning the analogue/background docs into first-class incident evidence?

## Fast reference - most important facts to remember

- Main incident is the **March 19 second compromise** of Trivy ecosystem components.
- Official safe anchors: `trivy-action 0.35.0`, `setup-trivy 0.2.6`, `trivy <=0.69.3`.
- Main C2 / hunt pivot: `scan.aquasecurtiy[.]org`.
- Main fallback exfil pivot: `tpcp-docs`.
- Docker follow-on matters: `0.69.5`, `0.69.6`, `latest`.
- CanisterWorm is a **follow-on worm campaign**, not the original compromise.
- OpenVSX is a **related earlier compromise**, not the March 19 tag-hijack event.
- `hackerbot-claw` explains earlier foothold context.
- `Shai-Hulud 2.0` is comparison material only.

## End state

These notes are the persistent baseline for future comparison work on this hunt package.  
They are intentionally optimized for **evaluation of completeness, source separation, and factual discipline**, not for publication.

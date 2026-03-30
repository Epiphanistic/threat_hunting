# Trivy Ecosystem Supply Chain Compromise - Query Priorities
These are high-signal scoping priorities aligned to the hunt. This folder does not yet include a fully built platform-specific LogScale pack.

## Workflow and runner scoping
- Identify workflows and runners that resolved `aquasecurity/trivy-action`, `aquasecurity/setup-trivy`, or `trivy` during the March 19 exposure windows.
- Include older `trivy-action` SHA-pinned workflows where `setup-trivy` could still have resolved during its exposure window.

## Runner theft sequence
- Identify access to `/proc/*/environ`, `/proc/*/maps`, or `/proc/*/mem` where the acting process is linked to a Trivy step.
- Identify unexpected shell or Python execution before normal Trivy scan behavior.

## Network and fallback exfiltration
- Identify outbound DNS or HTTPS to `scan.aquasecurtiy.org`, `45.148.10.212`, `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`, or GitHub activity tied to `tpcp-docs`.

## Docker follow-on
- Identify Docker pulls or container starts for digests `27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3`, `5aaa1d7cfa9ca4649d6ffad165435c519dc836fa6e21b729a2174ad10b057d2b`, and `425cd3e1a2846ac73944e891250377d2b03653e6f028833e30fc00c1abbc6d33`.
- Review runtime context for mounted secrets, cloud credentials, Kubernetes tokens, and Docker socket access.

## CanisterWorm follow-on
- Where npm follow-on is in scope, identify creation of `~/.config/systemd/user/pgmon.service`, writes under `~/.local/share/pgmon/`, execution from `/tmp/pglog`, and polling of `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`.

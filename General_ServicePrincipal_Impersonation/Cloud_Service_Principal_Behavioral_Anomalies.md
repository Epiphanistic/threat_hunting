# Cloud Service Principal Behavioral Anomalies (Generic)

## Executive summary
Identify anomalous usage of any service principal (SP) across the estate. Focus on deviations in
who/what is using the SP (source networks, software identity), what it touches (API families,
scope/resources), and how it authenticates (credential material), while ignoring temporal cadence (no
time-of-day or burst analysis).

## Risk if true
- Unauthorized use of SPs for privileged actions across cloud control planes.
- Persistence via added credentials or altered auth methods.
- Data access or modification in unexpected services/resources.
- Lateral movement across regions/compartments/projects using SP tokens.

## Hypothesis
If a threat actor abuses SP credentials/tokens or attaches alternate authentication material, we will
observe per-SP deviations in: source IP/ASN, user agent/SDK, API/service families accessed,
regions/compartments/projects touched, and credential lifecycle events, plus IAM/policy/object
changes, without relying on time-based patterns.

## Scope
- In-scope: all tenants/subscriptions/compartments/projects and all service principals.
- Time window: last 30 days (expand to 90 if needed).
- Out-of-scope by default: time-of-day drift, burst/cadence anomalies.

## MITRE mapping
- T1078.004 - Valid Accounts: Cloud Accounts (Initial Access, Persistence, Privilege Escalation)
- T1098.001 - Account Manipulation: Additional Cloud Credentials (Persistence/Privilege Escalation)
- T1550.001 - Use Alternate Authentication Material: Application Access Token (Lateral Movement/Defense Evasion)
- T1528 - Steal Application Access Token (Credential Access)
- T1606.002 - Forge Web Credentials: SAML Tokens (context-dependent)

## Data sources
- Cloud audit/management logs (e.g., OCI Audit / AWS CloudTrail / Azure Activity / GCP Admin Activity).
- IdP/app registrations (e.g., IDCS / Entra ID / IAM): app updates, client secret/cert events, token grants.
- Key/secret management (Vault/KMS) events.
- Endpoint EDR on runners/hosts invoking cloud SDK/CLI.
- CI/CD job logs invoking SPs.
- Network egress/flow for runner hosts (IP ownership/ASN).

## Expected outcome
- Tiered outputs: likely authorized (approved IP/ASN, expected UAs, known owners); suspicious/requires
  escalation (new IP/ASN, new APIs/scope, credential events); confirmed abuse (credential changes plus
  anomalous access patterns).
- Deliverables: per-SP anomaly report with evidence; diff vs baseline across source/IP/ASN, UA,
  API family, scope, auth material.
- Tuning: allowlist for corporate egress, sanctioned runners, and known SP usage patterns.

## General queries
Moved to: [Cloud service principal general queries](Cloud_Service_Principal_General_Queries.md)

## Triage and response tips
- New/rare IPs or ASNs for an SP; IPs outside corporate ranges.
- User-agent change (e.g., CI runner SDK to raw curl).
- First-time API family/service (e.g., Secrets/Vault) for that SP.
- First-time region/compartment/project touched.
- Credential events (new secret/cert) correlated with API activity.
- IAM/secret/policy actions executed by an SP normally scoped to non-IAM workloads.
- Auth method change with no approved change.

## Validation
- Attribute IPs to corp ranges or approved cloud egress; pull ASN/ownership.
- Map UAs to approved runners/agents; verify build IDs/change tickets.
- Check repo/CI history for legitimate pipeline changes.
- Inspect IdP app registration: recent updates, added credentials, consent/grants.
- On runners, confirm process lineage and credential file locations; look for ad-hoc shells preceding
  API calls.

## Containment (if abuse suspected)
- Rotate SP secrets/keys; revoke tokens.
- Remove newly added credentials; lock or disable the SP if needed.
- Restrict SP policies to least privilege; block offending IPs.
- Snapshot relevant configs/resources for forensics; preserve logs.

## Deliverables
- Per-SP anomaly report (CSV/JSON) with evidence.
- Diff vs baseline: source/IP/ASN, UA, API family, scope, auth material.
- Assessment: Confirmed / Likely / Unlikely abuse.
- Hardening plan: monitoring rules and policy/credential hygiene.

## Exit criteria
- No unexplained anomalies across SPs for the window, or anomalies fully explained with evidence.
- Detections deployed: alert on new IP/ASN; new UA/SDK; new API family; new
  region/compartment/project; credential added/rotated; IAM/secret/policy actions executed by SPs.

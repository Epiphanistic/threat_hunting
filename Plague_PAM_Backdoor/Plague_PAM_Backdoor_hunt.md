# Plague PAM-Based Backdoor (T1556.003)

## Executive summary
Plague is a Linux backdoor implemented as a malicious PAM module that
hijacks authentication (notably SSH) and can bypass standard credential
checks. It persists by embedding itself in core PAM flows and can survive
routine application updates, making SSH access a high-risk entry point.
This hunt focuses on detecting unauthorized PAM configuration/module
writes, known Plague hashes, and related authentication artifacts.

## Risk if true
- Covert SSH access via PAM authentication bypass.
- Persistence in core Linux auth pipeline (pam_authenticate).
- Long-lived access that survives common updates and package changes.
- Stealthy backdoor activation using static passwords.

## Hypothesis
If Plague is present, systems will show non-package-manager processes
writing to `/etc/pam.d/` or PAM module directories (e.g., `/lib64/security/`).
SSH authentication may succeed using static backdoor passwords, and the
infected host will contain known Plague hashes. PAM module tampering is
most likely tied to `sshd` and should correlate with unusual file writes
or integrity events.

## Scope
- In-scope: Linux servers, especially SSH-accessible hosts.
- Time window: last 7-30 days for behavioral writes; 7 days for hashes.
- Out-of-scope: ephemeral containers unless host PAM directories are exposed.

## MITRE mapping
- T1556.003 - Modify Authentication Process: Pluggable Authentication Modules.
  Detect via PAM config/module writes and SSH authentication anomalies.
- T1547.006 - Boot or Logon Autostart Execution: PAM modules (persistence).
  Detect via unauthorized changes in `/etc/pam.d/` and `/lib64/security/`.
- T1078 - Valid Accounts (Defense Evasion): Backdoor passwords used for login.
  Detect by unusual auth success with static/password-trigger behavior.

## Data sources
- EDR process and file-integrity telemetry on Linux.
- File monitoring for `/etc/pam.d/` and `/lib*/security/*.so`.
- SSH auth logs (`/var/log/auth.log`, `/var/log/secure`).
- Package manager logs for baseline exclusions (yum/dnf).

## Expected outcome
- Host list with suspicious PAM config/module writes.
- Matches on known Plague hashes.
- Correlated SSH auth activity inconsistent with normal credentials.

## LogScale queries
Moved to: [Plague PAM LogScale queries](Plague_PAM_Backdoor_Logscale_queries.md)

## Indicators of compromise
### File hashes (SHA256)
- 85c66835657e3ee6a478a2e0b1fd3d87119bebadc43a16814c30eb94c53766bb
- 7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e
- 9445da674e59ef27624cd5c8ffa0bd6c837de0d90dd2857cf28b16a08fd7dba6
- 5e6041374f5b1e6c05393ea28468a91c41c38dc6b5a5230795a61c2b60ed14bc
- e594bca43ade76bbaab2592e9eabeb8dca8a72ed27afd5e26d857659ec173261
- 6d2d30d5295ad99018146c8e67ea12f4aaa2ca1a170ad287a579876bf03c2950
- 14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39
- f62624d28aaa0de93e49fcdaaa3b73623723bdfb308e95dcbeab583bdfe3ac64
- 24d71c0524467db1b83e661abc2b80d582f62fa0ead38fdf4974a64d59423ff1
- 5aeae90e3ab3418ef001cce2cddeaaaea5e4e27efdad4c6fa7459105ef6d55fa
- ae26a4bc9323b7ae9d135ef3606339ee681a443ef45184c2553aa1468ba2e04b
- ac32ed04c0a81eb2a84f3737affe73f5101970cc3f07e5a2e34b239ab0918edd

### Backdoor passwords (from analysis)
- Mvi4Odm6tld7
- IpV57KNK32Ih
- changeme

### PAM-related paths (monitor for writes)
- /etc/pam.d/sshd
- /etc/pam.d/*
- /lib/security/*.so
- /lib64/security/*.so
- /usr/lib/security/*.so
- /usr/lib64/security/*.so

## Triage and response tips
- Confirm PAM file changes against package manager updates and change tickets.
- Validate whether sshd PAM configs were altered outside normal maintenance.
- Inspect suspicious processes writing to PAM directories.
- Check auth logs for anomalous successful logins or unusual usernames.

## Validation
- Verify hash matches against known Plague samples.
- Compare PAM configuration against known-good baselines.
- Confirm file ownership, timestamps, and package integrity for PAM modules.

## Containment
- Isolate affected hosts and rotate SSH credentials/keys.
- Restore PAM configuration from trusted sources.
- Remove malicious PAM modules and re-verify integrity.
- Tighten privileges to limit PAM installation paths.

## Deliverables
- Host list with evidence of PAM tampering.
- Hash match report for Plague samples.
- SSH auth anomaly report and remediation status.

## Exit criteria
- No unauthorized PAM file writes in the monitoring window.
- No hash matches for Plague samples.
- SSH auth patterns align with baselines and approved access.

## References
https://www.cyberark.com/resources/blog/plague-malware-exploits-pluggable-authentication-module-to-breach-linux-systems
https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/
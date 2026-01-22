# Silk Typhoon (HAFNIUM) / UNC5221 Behavioral Hunt

## Executive summary
Silk Typhoon (HAFNIUM) is a China-based espionage actor known for targeting
healthcare, law firms, higher education, defense contractors, policy think
tanks, and NGOs, and for leveraging zero-day exploits alongside web shell
tooling. Google Threat Intelligence Group (GTIG) reports a separate cluster,
UNC5221, that targeted US legal services, SaaS, BPOs, and technology firms
with long dwell times and a BRICKSTORM backdoor deployed on edge appliances
and vCenter infrastructure, and notes UNC5221 as distinct from Silk Typhoon.
This hunt focuses on behavioral signals tied to cloud-fronted C2, tunneling,
and suspicious authentication activity that align with those tradecraft
patterns.

## Risk if true
- Covert access via BRICKSTORM backdoor on edge appliances or management
  servers.
- Credential interception on vCenter login paths and valid-account abuse.
- Stealthy data access via VM cloning or snapshot operations.
- Cloud-fronted C2 using Cloudflare/Heroku infrastructure and DoH.
- Long dwell time leading to extended espionage or data theft.

## Hypothesis
If UNC5221 or a related Silk Typhoon operation is present, initial access
likely occurs through internet-facing appliances, followed by deployment of
the BRICKSTORM backdoor and optional server-side components (e.g., servlet
filters or web shells) on vCenter paths to capture credentials. Attackers
then pivot using valid accounts into vCenter/ESXi, enable SSH or API access,
and quietly clone or snapshot VMs for offline data collection. Related
reporting also describes ESXi and guest implants (Junction and GuestConduit)
in similar vCenter intrusions. Command and control is expected to leverage
cloud-fronting (Cloudflare Workers, Heroku) and WebSocket-based channels,
with DNS and tunnel indicators visible before or during later-stage
authentication abuse.

## Scope
- In-scope: edge appliances, vCenter/ESXi hosts, and management networks.
- Time window: 30-90 days for DNS/auth pivots; 1 year for asset inventory.
- Out-of-scope: cloud-only tenants with no on-prem virtualization estate.

## MITRE mapping
- T1071.001 - Application Layer Protocol: Web Protocols: detect non-browser
  DNS traffic to *.workers.dev and *.herokuapp.com as in the LogScale
  Cloudflare/Heroku C2 query.
- T1568.003 - Dynamic Resolution: DNS patterns such as trycloudflare.com and
  cfargotunnel domains aligned to the tunnel-correlation query logic.
- T1090.002 - Proxy: External Proxy: cloud-fronted C2 via Cloudflare/Heroku
  inferred from DNS joins between tunnel and workers/heroku domains.
- T1110 - Brute Force and T1078 - Valid Accounts: correlate failed logons
  followed by successful access from the same IP (LogScale brute-force
  sequence queries).
- T1005 - Data from Local System: validate VM clone or snapshot activity in
  vCenter logs alongside network/DNS indicators.

## Data sources
- DNS logs and proxy telemetry for cloud-fronted C2 patterns.
- vCenter/vpxd, VAMI, and ESXi auth logs (SSH, API, SSO events).
- EDR or host telemetry from appliances and management servers.
- Network flow/IDS for WebSocket over HTTPS patterns.
- VMware inventory logs for snapshots/clones and VM export operations.

## Expected outcome
- Host list of appliances or vCenter systems with suspicious DNS or auth
  behavior.
- Correlated events showing tunnel usage and post-bruteforce access.
- Evidence of VM clone/snapshot activity tied to suspicious sessions.
- Remediation plan for credentials, appliance hardening, and access review.

## LogScale queries
Moved to: [Silk Typhoon / UNC5221 LogScale queries](SilkTyphoon_UNC5221_Logscale_queries.md)

## Indicators of compromise
### C2 and tunnel patterns
- *.workers.dev (Cloudflare Workers)
- *.herokuapp.com, *.herokudns.com (Heroku fronting)
- *.trycloudflare.com, cfargotunnel domains
- Cloud-fronted HTTPS/WebSocket sessions from non-browser processes

### Masquerade and tooling cues
- Process names observed in reports: vami-http, updatemgr (masquerade)
- BRICKSTORM backdoor on appliance or management nodes
- BRICKSTEAL servlet filter on vCenter login paths and SLAYSTYLE webshells
- Junction and GuestConduit implants on ESXi or guest VMs

## Triage and response tips
- Inspect DNS logs for non-browser lookups to Cloudflare/Heroku endpoints.
- Review vCenter auth logs for brute-force sequences and same-IP success.
- Check for unexpected SSH enablement or API login bursts on ESXi hosts.
- Investigate VM clones/snapshots created without corresponding change
  tickets or admin workflows.
- Validate appliance processes and binaries for BRICKSTORM masquerading.

## Validation
- Confirm suspicious DNS sessions map to appliance or vCenter processes.
- Verify successful logons correlate with earlier failures from same IP.
- Review vCenter task history for silent clone/snapshot operations.
- Cross-check with EDR or appliance integrity monitoring where available.

## Containment
- Reset credentials and rotate API tokens used by vCenter/ESXi admins.
- Isolate appliances with suspicious C2 activity for forensic triage.
- Remove malicious servlet filters or web shells from vCenter components.
- Enforce MFA and restrict management access to hardened jump hosts.

## Deliverables
- List of impacted appliances and vCenter/ESXi systems.
- Timeline of DNS/tunnel activity and correlated logon events.
- Evidence package for BRICKSTORM or related tooling artifacts.
- Detection tuning notes for cloud-fronted C2 and brute-force sequences.

## Exit criteria
- No suspicious DNS or tunnel activity in the monitoring window.
- No post-bruteforce successful logons from untrusted IPs.
- vCenter inventory free of unauthorized clone/snapshot activity.

## References
- https://cloud.google.com/blog/topics/threat-intelligence/unc5221-investigating-actively-exploited-zero-day-vulnerabilities
- https://www.microsoft.com/en-us/security/security-insider/silk-typhoon
- https://www.crowdstrike.com/blog/warps-panda-world-tour/

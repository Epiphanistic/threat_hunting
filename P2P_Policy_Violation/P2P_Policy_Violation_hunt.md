# P2P Policy Violation Hunt

## Executive summary
Peer-to-peer (P2P) applications and proxyware can create direct device-to-device
communications that bypass standard enterprise controls. The dashboard logic
targets common P2P clients, decentralized storage stacks (IPFS/libp2p), mesh
VPN overlays (ZeroTier/Hamachi), and Bright Data (Luminati) Bright SDK
components that can introduce unapproved data transfer paths. This hunt
identifies endpoints running these binaries or generating P2P DNS patterns
to support policy enforcement and data-loss prevention.

## Risk if true
- Unauthorized data movement outside approved collaboration channels.
- Encrypted or anonymized P2P traffic that evades proxy inspection.
- Proxyware or P2P overlays enabling covert access to internal systems.
- Increased exposure to malware delivered via P2P distribution.

## Hypothesis
If P2P policy violations exist, endpoints will show execution or installation
of known P2P or proxyware binaries, DNS activity tied to libp2p networks,
and Bright SDK indicators such as net_updater/net_svc components and
connections to Bright Data domains. Non-browser processes should appear
as the originators of these connections.

## Scope
- In-scope: Windows, macOS, and Linux endpoints with process, file-write,
  and DNS telemetry.
- Time window: 30-90 days for installs/execution; 1 year for DNS pivots.
- Out-of-scope: sanctioned P2P tooling approved by exception (documented
  allowlists).

## MITRE mapping
- T1071.001 - Application Layer Protocol: Web Protocols: Bright SDK and
  proxyware typically use HTTP/HTTPS; detect via Bright SDK file writes
  and net_updater/net_svc process hits.
- T1071.004 - Application Layer Protocol: DNS: detect libp2p DNS patterns
  using the non-browser DNS query that filters common browsers.
- T1090.002 - Proxy: External Proxy: identify proxyware and overlay VPN
  binaries via ProcessRollup2 regex coverage (e.g., Bright SDK, Hola,
  ZeroTier, Hamachi).

## Data sources
- EDR process execution and command-line telemetry.
- File-write telemetry for PE files and binary installs.
- DNS logs and proxy telemetry for libp2p and Bright SDK domains.
- Software inventory and endpoint allowlists for exception handling.

## Expected outcome
- Host list with P2P/proxyware binaries executed or installed.
- DNS hit list for libp2p and Bright Data domains from non-browser
  processes.
- Short list of hosts requiring exception review or remediation.

## LogScale queries
Moved to: [P2P Policy Violation LogScale queries](P2P_Policy_Violation_Logscale_queries.md)

## Indicators of compromise
### Bright SDK / Bright Data
- Executables: net_svc.exe, net_updater32.exe, net_updater64.exe,
  brightsvc.exe, lumprobe.exe (see LogScale regex list for variants)
- Domains: brdtnet.com, lum-sdk.io, bright-sdk.com
- DNS: *.probe.tbcache.com (from dashboard logic)

### High-risk P2P/proxyware examples (top 5)
- Hola VPN / Luminati (Bright Data): proxyware model that can turn endpoints
  into exit nodes and has been publicly abused for large-scale DDoS activity.
- IPFS/libp2p stacks: decentralized content hosting that has been used in
  phishing campaigns.
- I2P: anonymized, encrypted P2P network that obscures sender/receiver identity
  and can be abused to mask C2 or exfil channels.
- ZeroTier: mesh VPN overlay that creates a virtual LAN and can bypass
  segmentation controls.
- Resilio Sync / BitTorrent Sync: peer-to-peer file synchronization that can
  move data off-network outside approved channels.

### P2P and overlay tooling (examples)
- IPFS/libp2p stacks: ipfs, go-ipfs, js-ipfs
- Mesh VPN: zerotier-one, hamachi-2
- Sync and sharing: Resilio Sync, BitTorrent clients, Syncthing
- Anonymity networks: i2p, tor, zeronet

### Other in-scope tooling and why
All remaining binaries in the query list stay in scope because they
enable unsanctioned peer-to-peer transfer, create encrypted overlays,
or participate in decentralized networks that bypass centralized
egress controls and standard DLP/inspection tooling. Even when not
inherently malicious, these tools introduce unmanaged data movement
paths, expand the external attack surface, and complicate incident
response by obscuring ownership and traffic attribution.

## Triage and response tips
- Validate binaries (path, signer, hash) and confirm if approved.
- Review user context and parent process for lateral or covert usage.
- Correlate DNS hits with process execution and file writes.
- Check for bulk data access or large outbound transfer volumes.

## Validation
- Confirm processes match approved software inventory or exception list.
- Verify DNS hits are from non-browser processes.
- Inspect install artifacts and persistence (services, scheduled tasks).

## Containment
- Remove unauthorized P2P/proxyware software.
- Block known domains and ports used by P2P overlays.
- Enforce egress controls and restrict endpoint admin installs.

## Deliverables
- Inventory of endpoints with P2P/proxyware binaries.
- DNS and file-write evidence supporting policy violations.
- Remediation/exception tracking list for owners and SOC.

## Exit criteria
- No unauthorized P2P binaries or Bright SDK artifacts remain.
- No libp2p or Bright Data DNS activity from non-browser processes.

## References
- https://docs.ipfs.tech/concepts/libp2p/
- https://libp2p.io/
- https://help.resilio.com/hc/en-us/articles/204754759-What-ports-and-protocols-are-used-by-Sync
- https://docs.zerotier.com/protocol/
- https://help.bright-sdk.com/hc/en-us/articles/20079623475217-What-does-Bright-SDK-do
- https://www.netify.ai/resources/applications/bright-data
- https://arstechnica.com/information-technology/2015/06/hola-vpn-used-to-perform-ddos-attacks-violate-user-privacy/
- https://www.kaspersky.com/about/press-releases/scammers-go-interplanetary-using-decentralized-file-system-in-their-campaigns
- https://beta.i2p.net/en/docs/overview/intro/
- https://docs.zerotier.com/start
- https://docs.resilio.com/

# DLL Sideloading Campaign abusing ahost.exe OSINT Report
Date: 2026-02-08

## Executive Summary
- Trellix disclosed on January 14, 2026 a campaign where threat actors abuse signed `ahost.exe` to sideload malicious `libcares-2.dll`.
- The tradecraft is effective because it borrows trust from a legitimate executable while moving malicious logic into a side-loaded dynamic link library.
- Reported follow-on activity includes infostealers and remote access trojans, including DCRat and XWorm.

## Campaign Profile
- Pattern type: signed binary proxy execution plus dynamic link library search order abuse.
- Operational style: reusable loader pattern observed across multiple malware clusters.
- Likely objective set: credential theft, foothold establishment, and remote command execution.

## Component Legitimacy and Abuse
### `ahost.exe`
- Legitimate role: utility component tied to c-ares DNS functionality in normal software distribution contexts.
- Abuse pattern: copied or renamed into staging path and used to trigger malicious library load.

### `libcares-2.dll`
- Legitimate role: c-ares asynchronous DNS resolver dynamic link library.
- Abuse pattern: attacker supplies a malicious DLL with same name so trusted executable loads attacker code.

### `AddInProcess32.exe`
- Legitimate role: Microsoft add-in host process used by extensibility components.
- Abuse pattern: used as injection or execution host to reduce suspicion and blend with expected enterprise process names.

### `dgflex.duckdns.org`
- Legitimate context: Duck DNS is a legitimate dynamic DNS provider.
- Abuse context: dynamic DNS is commonly used to rotate command-and-control infrastructure.

## Timeline
- 2026-01-14: Trellix publishes campaign details and indicators.
- 2026-01-14 onward: secondary outlets replicate campaign narrative and malware family overlap.
- 2026-02-08: hunt package consolidated with supporting ATT&CK, Microsoft, c-ares, and infrastructure context.

## Who Uses This Method
- DLL sideloading is widely used by both criminal and state-linked operators.
- ATT&CK procedure examples for `T1574.001` and `T1218` confirm broad ecosystem adoption.
- Defensive implication: prioritize behavior-chain detections with path and lineage checks over pure indicator matching.

## MITRE ATT&CK Mapping
- Reconnaissance: unknown. Public reporting and collected source set do not expose a verified pre-compromise targeting workflow for this cluster.
- Resource Development: unknown. The observed `dgflex.duckdns.org` shows active infrastructure use, but preparation stage details are not evidenced.
- Initial Access: unknown. The analyzed campaign material does not attribute a single confirmed initial compromise mechanism in this package.
- Execution: `T1218` System Binary Proxy Execution. Attackers execute signed `ahost.exe` to proxy malicious execution and inherit trust from a legitimate binary.
- Persistence: unknown. Available artifacts do not confirm durable foothold mechanisms such as autoruns, services, or scheduled tasks.
- Privilege Escalation: unknown. No validated evidence of elevation technique appears in the current hunt corpus.
- Defense Evasion: `T1574.001` Dynamic Link Library Search Order Hijacking; `T1036` Masquerading. The malicious `libcares-2.dll` is loaded through sideload conditions, and naming/placement choices reduce operator visibility.
- Credential Access: unknown. While downstream families are credential-theft capable, no direct credential access telemetry is established in this data.
- Discovery: unknown. The collected reporting does not provide a reliable, repeatable discovery command sequence for this campaign.
- Lateral Movement: unknown. No confirmed cross-host propagation behavior is documented in scoped evidence.
- Collection: unknown. There is no direct proof here of local data staging or collection tasks preceding command-and-control traffic.
- Command and Control: `T1071.004` Domain Name System. Duck DNS infrastructure, including `dgflex.duckdns.org`, supports domain resolution behavior consistent with command-and-control routing.
- Exfiltration: unknown. No source in scope confirms data theft channel, protocol, or volume for this operation.
- Impact: unknown. No evidence in this hunt indicates destructive or service-impacting post-compromise objectives.

Supporting detail:
- `T1055` Process Injection is reported in the DCRat branch through `AddInProcess32.exe`; classify as supported-but-conditional until endpoint memory evidence confirms local injection on investigated hosts.

## Detection Guidance
- Correlate abnormal `ahost.exe` path with near-time `libcares-2.dll` evidence.
- Treat `AddInProcess32.exe` as suspicious only when upstream sideload chain exists.
- Use hash and domain indicators to confirm or scope, not to drive initial triage.

## Hardening Guidance
- Enforce secure dynamic link library loading controls where feasible.
- Reduce broad process trust assumptions in application control policies.
- Avoid broad antivirus exclusions for bypass-prone processes.

## Source Confidence
- High confidence: tradecraft pattern and behavioral chain.
- Medium confidence: static indicators and infrastructure longevity.

## Sources
- https://www.trellix.com/en-au/blogs/research/hiding-in-plain-sight-multi-actor-ahost-exe-attacks/
- https://thehackernews.com/2026/01/hackers-exploit-c-ares-dll-side-loading.html
- https://www.cybersecurity-help.cz/blog/5173.html
- https://any.run/report/7b66bf96c2e5c9a8acdc44f16453b182588f21767d4c0e06eaf9936f033f57db/f30de6d0-3cbc-4909-9f08-1154abf060ff
- https://any.run/report/82531a17e0d2643d8da9bf5ecbcfe7a54f998ee45f37d2905343f42d2f6687ce/8dd88d86-39af-45ef-abf2-9263b2b85170
- https://any.run/report/e2f7f2575e47b94221296f42d0e9b4b3ca3789e27e34f75efca6eb58c6742f96/9f5a218d-6fa8-4a03-8345-972f34bf0da6
- https://hybrid-analysis.com/sample/66563bbfca3caf9f4cce9859a6fbbf65c73d919f07f88f76f4f0315ec3ad99d0/67de3fc0ec2afcc68f01bb81
- https://hybrid-analysis.com/sample/6deb53f0ef8b5ca911f31f0b302f3060f50a4d6bef9af3a6aef542e8d0d6f264/67040ca2f3502dbf650dcff7

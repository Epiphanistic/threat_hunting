# DLL Sideloading Campaign abusing ahost.exe - Hunt Playbook
Companion context is in `DLL_Sideloading_Campaign_abusing_ahost_exe_OSINT_report.md`.

## Executive Summary
This hunt targets a signed-binary abuse chain: `ahost.exe` execution from suspicious context, malicious `libcares-2.dll` load behavior, and follow-on process activity that can include DCRat running through `AddInProcess32.exe`.

## Objective
- Detect confirmed `ahost.exe` plus `libcares-2.dll` sideload chains.
- Identify downstream suspicious execution, including potential injection patterns.
- Produce host-level containment and scoping outcomes.

## Hypothesis
If campaign activity exists, telemetry will show:
- `ahost.exe` execution outside expected software paths,
- near-time evidence of `libcares-2.dll` in the same chain,
- suspicious child process, injection, or command-and-control behavior.

## Scope
- Platform: Windows endpoints.
- Required telemetry: process creation, file write, DNS, and preferably module/load or memory behavior.
- Time window: 2026-01-14 onward.

## Process Legitimacy Baseline
- `ahost.exe`: legitimate in expected install context; suspicious in archive extraction or user profile paths.
- `libcares-2.dll`: legitimate library name; suspicious when path/lineage indicates sideload setup.
- `AddInProcess32.exe`: legitimate add-in host; suspicious when linked to sideload chain.

## MITRE ATT&CK Mapping
- Reconnaissance: unknown. Current hunt data starts at host execution telemetry and does not include adversary pre-compromise intelligence activity.
- Resource Development: unknown. No evidence in scope for attacker infrastructure build-out beyond already-active dynamic DNS usage.
- Initial Access: unknown. The campaign reporting and local hunt artifacts do not provide confirmed entry vector in this dataset.
- Execution: `T1218` System Binary Proxy Execution. Adversaries execute signed `ahost.exe` from suspicious paths so malicious code runs under trusted binary context.
- Persistence: unknown. This hunt package has no confirmed scheduled task, service, run key, or startup folder persistence tied to the chain.
- Privilege Escalation: unknown. No token abuse, exploit, or elevated privilege transition is confirmed in available telemetry.
- Defense Evasion: `T1574.001` Dynamic Link Library Search Order Hijacking; `T1036` Masquerading. The core chain abuses DLL load order with fake `libcares-2.dll`, and process naming/path context blends with legitimate software.
- Credential Access: unknown. Malware families in reporting can support theft, but this hunt evidence does not directly confirm credential dumping or browser credential extraction events.
- Discovery: unknown. No reliable host or network discovery command sequence is currently tied to confirmed cases in scope.
- Lateral Movement: unknown. No remote service creation, remote process execution, or admin share propagation is confirmed from current data.
- Collection: unknown. There is no direct telemetry in this hunt proving staged local data collection before command-and-control communication.
- Command and Control: `T1071.004` Domain Name System. Domain pivots include `dgflex.duckdns.org` and broader Duck DNS patterns, consistent with DNS-mediated command-and-control resolution.
- Exfiltration: unknown. No verified outbound data theft channel is proven in current timeline.
- Impact: unknown. No destructive, disruptive, or extortion outcome is evidenced in this hunt scope.

Known supporting technique:
- `T1055` Process Injection (reported in DCRat branch through `AddInProcess32.exe`; treat as conditional until memory telemetry confirms injection behavior on affected hosts).

## Hunt Approach
1. Identify suspicious `ahost.exe` executions by path and parent process.
2. Correlate `libcares-2.dll` file or command evidence in same host timeline.
3. Pivot to `AddInProcess32.exe` behavior and suspicious lineage.
4. Correlate DNS and network artifacts to raise confidence.
5. Confirm with IOC matches for scoping and case expansion.

## Triage Logic
- Low confidence: isolated indicator hit without chain.
- Medium confidence: path + lineage anomalies without network corroboration.
- High confidence: full chain with supporting DNS/network or injection evidence.

## Response Actions
- Isolate confirmed hosts.
- Acquire process trees, file events, and memory artifacts where available.
- Block validated domains and hashes through approved controls.
- Hunt adjacent hosts and user contexts for same behavior pattern.

## Exit Criteria
- No confirmed sideload behavior chain in scoped telemetry.
- Confirmed cases are contained and remediated.
- Detection logic rerun yields no unresolved high-confidence findings.

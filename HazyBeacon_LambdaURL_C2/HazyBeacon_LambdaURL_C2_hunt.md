# HazyBeacon / Lambda URL Covert C2 Hunt

## Executive summary
Unit 42 reported a cluster tracked as CL-STA-1020 targeting Southeast Asian
government entities with a novel Windows backdoor (HazyBeacon) that uses
AWS Lambda function URLs (lambda-url.<region>.on.aws) as covert C2. This
technique blends malicious C2 into trusted cloud traffic and can evade
traditional network controls. DarkReading notes Trellix first described
Lambda URL abuse for C2 in late June 2025, suggesting this technique is
emerging beyond a single campaign. This hunt focuses on non-browser DNS
requests to Lambda URL domains and correlates them with endpoint detections
and suspicious process context.

## Risk if true
- Covert C2 over legitimate AWS domains, complicating network detection.
- Persistence via DLL sideloading and service-based execution.
- Targeted data collection and exfiltration using cloud storage services.
- Long dwell time due to trusted cloud traffic blending.

## Hypothesis
If Lambda URL C2 is active, endpoints will generate DNS queries to
<url-id>.lambda-url.<region>.on.aws from non-browser processes, often
paired with suspicious binaries or EDR detections. In HazyBeacon-like
activity, DLL sideloading (mscorsvc.dll + mscorsvw.exe) and a persistence
service (msdnetsvc) are expected. Subsequent tooling may stage data and
exfiltrate via Google Drive or Dropbox.

## Scope
- In-scope: Windows endpoints, DNS logs, EDR detections, and proxy logs.
- Time window: 30 days for C2 detection; 6–12 months for baseline trends.
- Out-of-scope: known sanctioned Lambda URL endpoints for internal apps.

## MITRE mapping
- T1071.001 - Application Layer Protocol: Web Protocols (HTTPS to Lambda URLs).
- T1102 - Web Service: C2 over legitimate AWS Lambda endpoints.
- T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking (sideloading).
- T1543.003 - Create or Modify System Process: Windows Service (msdnetsvc).

## Data sources
- DNS logs with process context (DnsRequest/SuspiciousDnsRequest).
- EDR detection summaries and process telemetry.
- Windows service creation logs (if available).
- Proxy/Netflow data for HTTPS to on.aws domains.

## Expected outcome
- Host list of non-browser Lambda URL DNS requests.
- Correlated detections tied to suspicious processes or DLL sideloading.
- Remediation actions for confirmed Lambda URL C2 activity.

## LogScale queries
Moved to: [HazyBeacon Lambda URL C2 LogScale queries](HazyBeacon_LambdaURL_C2_Logscale_queries.md)

## Indicators of compromise
### Lambda URL pattern
- https://<url-id>.lambda-url.<region>.on.aws (Lambda function URL format).

### Files and persistence (Unit 42 / Securonix reporting)
- C:\Windows\assembly\mscorsvc.dll (malicious DLL via sideloading)
- C:\Windows\Microsoft.NET\Framework\*\mscorsvw.exe (legitimate loader)
- Service: msdnetsvc (persistence)
- C:\ProgramData\7z.exe, igfx.exe, GoogleGet.exe, google.exe,
  GoogleDrive.exe, GoogleDriveUpload.exe, Dropbox.exe (payloads/exfil tools)

### Hashes (SHA256)
- 4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30
- d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa
- 304c615f4a8c2c2b36478b693db767d41be998032252c8159cc22c18a65ab498
- f0c9481513156b0cdd216d6dfb53772839438a2215d9c5b895445f418b64b886
- 3255798db8936b5b3ae9fed6292413ce20da48131b27394c844ecec186a1e92f
- 279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e
- d961aca6c2899cc1495c0e64a29b85aa226f40cf9d42dadc291c4f601d6e27c3

## Known APTs / clusters using Lambda URL C2 (public reporting)
- CL-STA-1020 (Unit 42 cluster; HazyBeacon campaign).
- Trellix-reported APT activity using Lambda URL C2 (actor name not public).

## Behavioral signals from internal observations
- Non-browser Lambda URL DNS from WmiPrvSE.exe with parent svchost.exe and
  scheduled task launch context (ProcessRollup2-style chains).
- Scheduled tasks launching system components that then perform outbound
  HTTPS/DNS to lambda-url.*.on.aws.
- Unusual or unknown binaries tied to task/service context (e.g.,
  SeamlessUpdater.Server.exe, Obsidian Helper, wmiadap.exe /F /T /R).
- System-account network activity (e.g., S-1-5-20 / machine account) to
  lambda-url domains without a documented business use case.
- Unsigned or signer-mismatch binaries making Lambda URL callbacks.

## Confidence guidance
- High-confidence: known-malicious hash, confirmed command responses over
  Lambda URL C2, multiple hosts with the same scheduled task/binary chain.
- Suspicious: Lambda URL DNS from system processes, unknown tasks/services,
  or unusual updater/helper binaries without clear provenance.

## Observed use cases
### Immediate triage checklist (from observed cases)
1. Isolate the host if confirmed C2 activity is present or confidence is high.
2. Collect evidence:
   - Scheduled task definition (XML) and task history.
   - Full process creation chain and command lines (path, parent, token/user).
   - Memory/process dump of suspicious process (EDR) if allowed.
   - DNS logs showing lambda-url.*.on.aws queries.
   - File artifacts for suspicious executables; capture hashes.
3. Enrich hashes and domains (VirusTotal, internal allowlists).
4. Hunt for the same domain patterns and hashes across the estate.
5. Hunt for persistence: scheduled tasks, services, Run keys, WMI consumers.
6. Capture network metadata (SNI, TLS certs, JA3) for Lambda URL traffic.
7. Remediate: disable task/service, remove artifacts, rotate credentials.

### Quick decision flow (observed cases)
- Single host, no confirmed payloads yet, but task → system process → Lambda URL
  pattern present: quarantine, collect artifacts, escalate to IR.
- Multiple hosts or confirmed command responses/exfiltration: activate full IR,
  block lambda-url endpoints, and perform enterprise-wide containment.

## Triage and response tips
- Validate whether Lambda URL domains are sanctioned business services.
- Pivot from DNS hits to process context, scheduled task lineage, and EDR detections.
- Hunt for DLL sideloading artifacts, unexpected Windows services, and scheduled tasks.
- Inspect outbound HTTPS to on.aws domains for unusual hosts or timing.

## Validation
- Confirm suspicious lambda-url domains resolve to AWS Lambda endpoints.
- Verify process lineage for non-browser DNS requests (task → svchost → WmiPrvSE).
- Check for msdnetsvc service creation and mscorsvc.dll replacement.

## Containment
- Isolate affected hosts and remove malicious DLLs/services.
- Block malicious lambda-url endpoints at DNS/proxy layers.
- Reset credentials and review cloud storage exfil paths.

## Deliverables
- Endpoint list with Lambda URL C2 indicators.
- IOC hit report (domains, hashes, service names).
- Recommendations for monitoring trusted cloud service abuse.

## Exit criteria
- No non-browser Lambda URL DNS activity over the monitoring window.
- No DLL sideloading or msdnetsvc persistence artifacts found.

## References
- https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
- https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html
- https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html
- https://www.darkreading.com/cloud-security/attackers-abuse-aws-southeast-asian-governments-novel-rat
- https://www.securonix.com/blog/securonix-threat-labs-monthly-intelligence-insights-july-2025/

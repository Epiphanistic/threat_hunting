# LiteLLM PyPI Supply-Chain Compromise — High-ROI KQL Queries

## Scope and assumptions
- Primary target platform: Microsoft Defender XDR Advanced Hunting.
- Primary tables: `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceInfo`.
- Optional AKS-specific queries: `AKSAudit`, `AKSAuditAdmin` in Azure Monitor / Microsoft Sentinel.
- These queries are written to be fast first, then expressive. They favor early filters, minimal regex, and concrete artifacts from the LiteLLM incident.
- Static IoCs used below are intentionally limited to the strongest public signals:
  - Malicious versions: `1.82.7`, `1.82.8`
  - Domains: `models.litellm.cloud`, `checkmarx.zone`
  - Files / paths: `litellm_init.pth`, `sysmon.service`, `sysmon.py`, `tpcp.tar.gz`, `session.key`, `payload.enc`, `session.key.enc`, `pglog`, `.pg_state`, `node-setup-*`

---

# Atomic detections

## Atomic 1 — Explicit installation or pinning of malicious LiteLLM versions
**MITRE:** T1195.001 — Compromise Software Dependencies and Development Tools

**Hypothesis**
If a device, build runner, or developer workstation explicitly installed or pinned the confirmed malicious versions of LiteLLM, process telemetry should show package-manager or Python command lines containing `litellm` with `1.82.7` or `1.82.8`.

**Scope**
Best fit: direct installs, explicit pins, troubleshooting confirmed exposure, and fast scoping of affected hosts. This query will not catch every transitive install when the version string never appears in the command line.

**Expected outcome**
A high-confidence list of devices and commands that directly referenced the malicious versions, useful for immediate triage, containment, and retrospective scoping.

```kusto
let lookback = 30d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("pip","pip3","uv","poetry","python","python3","py")
    or InitiatingProcessFileName in~ ("pip","pip3","uv","poetry","python","python3","py")
| where ProcessCommandLine has "litellm"
| where (ProcessCommandLine contains "1.82.7" or ProcessCommandLine contains "1.82.8")
    or (InitiatingProcessCommandLine contains "1.82.7" or InitiatingProcessCommandLine contains "1.82.8")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by Timestamp desc
```

---

## Atomic 2 — Suspicious Python startup hook (`.pth`) creation in site-packages / dist-packages
**MITRE:** T1546.018 — Event Triggered Execution: Python Startup Hooks

**Hypothesis**
The most distinctive tradecraft in the incident was the `litellm_init.pth` startup hook. If the malicious package was installed, endpoint file telemetry should show creation or modification of that `.pth` file in Python package directories, or at minimum a new `.pth` file in `site-packages` / `dist-packages` adjacent to LiteLLM-related execution.

**Scope**
This is one of the highest-ROI detections in the set. It is highly specific to the incident and also valuable for future Python package attacks that abuse `.pth` startup execution.

**Expected outcome**
A short, high-signal result set highlighting hosts where the malicious startup hook was dropped or altered.

```kusto
let lookback = 30d;
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "litellm_init.pth"
    or (
        FileName endswith ".pth"
        and FolderPath has_any ("/site-packages/","/dist-packages/","\\site-packages\\","\\dist-packages\\")
        and InitiatingProcessCommandLine has "litellm"
    )
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Atomic 3 — User-level systemd persistence (`sysmon.service` / `sysmon.py`)
**MITRE:** T1543.002 — Create or Modify System Process: Systemd Service

**Hypothesis**
Public reporting showed follow-on persistence via `~/.config/sysmon/sysmon.py` and `~/.config/systemd/user/sysmon.service`. If the payload reached its persistence stage, the expected evidence is file creation in those paths or `systemctl --user` commands enabling or starting the service.

**Scope**
Linux developer workstations, CI workers, and servers with Microsoft Defender for Endpoint on Linux telemetry. This is a strong follow-on detection and should be treated as materially more severe than package exposure alone.

**Expected outcome**
A narrow set of hosts with concrete persistence artifacts or the service-control commands used to activate them.

```kusto
let lookback = 30d;
let svcArtifacts =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where (FileName =~ "sysmon.service" and FolderPath has "/.config/systemd/user/")
    or (FileName =~ "sysmon.py" and FolderPath has "/.config/sysmon/")
| project Timestamp, DeviceId, DeviceName, EvidenceType="FileArtifact", FileName, FolderPath, Detail=coalesce(InitiatingProcessCommandLine, InitiatingProcessFileName);
let svcCtl =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "systemctl"
| where ProcessCommandLine has "--user"
| where ProcessCommandLine has_any ("sysmon","daemon-reload","enable --now","start")
| project Timestamp, DeviceId, DeviceName, EvidenceType="ServiceControl", FileName, FolderPath="", Detail=ProcessCommandLine;
union svcArtifacts, svcCtl
| order by Timestamp desc
```

---

## Atomic 4 — Exfiltration staging artifacts in temporary directories
**MITRE:** T1005 — Data from Local System; T1041 — Exfiltration Over C2 Channel

**Hypothesis**
The malware staged and encrypted collected data into temporary files before outbound transmission. If execution progressed beyond simple install, file telemetry should show creation or modification of known staging artifacts such as `tpcp.tar.gz`, `payload.enc`, and `session.key`.

**Scope**
Best fit: Linux endpoints and CI/CD runners. This is more valuable than network IoCs alone because it captures local malicious workflow even if egress was blocked or DNS was unavailable.

**Expected outcome**
Devices where local archive or encryption staging likely occurred and where deeper triage should immediately follow.

```kusto
let lookback = 30d;
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "/tmp/" or FolderPath has "\\Temp\\")
| where FileName in~ ("tpcp.tar.gz","session.key","payload.enc","session.key.enc","pglog",".pg_state")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Atomic 5 — Outbound network activity to confirmed campaign infrastructure
**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols; T1041 — Exfiltration Over C2 Channel

**Hypothesis**
If the payload successfully staged and transmitted data or polled follow-on infrastructure, network telemetry should show connections to `models.litellm.cloud` or `checkmarx.zone`, typically from Python, shell, or helper utilities such as `curl`.

**Scope**
Best fit: fast IOC scoping across endpoints. This should not be used as a stand-alone conclusion of compromise, but it is a strong correlation ingredient.

**Expected outcome**
A concise list of devices, processes, and destinations that intersect the strongest public network indicators.

```kusto
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemoteUrl contains "models.litellm.cloud" or RemoteUrl contains "checkmarx.zone"
| where InitiatingProcessFileName in~ ("python","python3","pip","pip3","uv","bash","sh","curl","wget")
    or InitiatingProcessCommandLine has "litellm"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

---

## Atomic 6 — Suspicious helper utilities launched by Python around archive, crypto, service, or C2 artifacts
**MITRE:** T1027, T1005, T1041, T1543.002

**Hypothesis**
Even when package-install visibility is weak, malicious Python execution often leaves follow-on process evidence. If the compromise progressed, Python or shell execution should spawn helper tools such as `curl`, `openssl`, `tar`, or `systemctl` with command lines referencing staging artifacts, C2 domains, or persistence files.

**Scope**
Best fit: a secondary atomic for endpoints where file events are partial or package-manager logging is weak.

**Expected outcome**
Short-list of suspicious process trees that deserve immediate device-level review.

```kusto
let lookback = 30d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("curl","wget","openssl","tar","zip","systemctl")
| where InitiatingProcessFileName in~ ("python","python3","bash","sh")
| where ProcessCommandLine contains "models.litellm.cloud"
    or ProcessCommandLine contains "checkmarx.zone"
    or ProcessCommandLine contains "tpcp.tar.gz"
    or ProcessCommandLine contains "payload.enc"
    or ProcessCommandLine contains "session.key"
    or ProcessCommandLine contains "sysmon.service"
    or ProcessCommandLine contains "sysmon.py"
    or InitiatingProcessCommandLine contains "litellm"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

# Complex behavioral chain detections backed by static IoCs

## Chain 1 — Weighted endpoint compromise score (install / `.pth` / staging / IOC egress / persistence)
**MITRE:** T1195.001, T1546.018, T1041, T1543.002

**Hypothesis**
A genuinely compromised endpoint should usually show more than one signal class across a short-to-medium time window: direct bad-version install, startup-hook drop, exfil staging artifacts, outbound traffic to known infrastructure, or user-level systemd persistence. A weighted score produces a more operationally useful queue than any single IOC-only hit.

**Scope**
Best fit: a primary production hunt for Defender XDR or Sentinel environments that ingest Defender raw event tables. This is the strongest first-pass high-fidelity detector in the set.

**Expected outcome**
A prioritized list of devices scored by breadth and strength of evidence, suitable for incident queueing and IR handoff.

```kusto
let lookback = 30d;
let installEvidence =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where ProcessCommandLine has "litellm"
| where ProcessCommandLine contains "1.82.7" or ProcessCommandLine contains "1.82.8"
| project DeviceId, DeviceName, Timestamp, Evidence="BadVersionInstall", Detail=ProcessCommandLine, Weight=4;
let pthEvidence =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "litellm_init.pth"
| project DeviceId, DeviceName, Timestamp, Evidence="PTHDrop", Detail=strcat(FolderPath, "/", FileName), Weight=5;
let stageEvidence =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where (FolderPath has "/tmp/" or FolderPath has "\\Temp\\")
| where FileName in~ ("tpcp.tar.gz","session.key","payload.enc","session.key.enc","pglog",".pg_state")
| project DeviceId, DeviceName, Timestamp, Evidence="TempStageArtifact", Detail=strcat(FolderPath, "/", FileName), Weight=4;
let persistEvidence =
union
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where (FileName =~ "sysmon.service" and FolderPath has "/.config/systemd/user/")
        or (FileName =~ "sysmon.py" and FolderPath has "/.config/sysmon/")
    | project DeviceId, DeviceName, Timestamp, Evidence="PersistenceArtifact", Detail=strcat(FolderPath, "/", FileName), Weight=5
),
(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName =~ "systemctl" and ProcessCommandLine has "--user" and ProcessCommandLine has "sysmon"
    | project DeviceId, DeviceName, Timestamp, Evidence="PersistenceActivation", Detail=ProcessCommandLine, Weight=4
);
let netEvidence =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemoteUrl contains "models.litellm.cloud" or RemoteUrl contains "checkmarx.zone"
| project DeviceId, DeviceName, Timestamp, Evidence="KnownBadNetwork", Detail=coalesce(RemoteUrl, RemoteIP), Weight=5;
union installEvidence, pthEvidence, stageEvidence, persistEvidence, netEvidence
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Score=sum(Weight), EvidenceCount=count(), Evidence=make_set(Evidence, 20), Details=make_set(Detail, 20) by DeviceId, DeviceName
| where Score >= 7 and EvidenceCount >= 2
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
) on DeviceId
| project FirstSeen, LastSeen, DeviceName, OSPlatform, Score, EvidenceCount, Evidence, Details
| order by Score desc, LastSeen desc
```

---

## Chain 2 — Tight attack-window correlation anchored on `.pth` startup-hook evidence
**MITRE:** T1546.018, T1041, T1543.002

**Hypothesis**
If the `.pth` hook was actually dropped, follow-on signs should often cluster close in time on the same device: temp staging artifacts, C2 traffic, or persistence artifacts. Anchoring on `.pth` and requiring additional signals reduces false positives from benign Python environments that also use `.pth` files.

**Scope**
Best fit: higher-fidelity triage after Atomic 2 or suppression of noise from benign package bootstrap behavior.

**Expected outcome**
A device-and-time-window view of likely true-positive chains where startup-hook abuse is corroborated by exfiltration or persistence behavior.

```kusto
let lookback = 30d;
let evidence =
union
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where ActionType in~ ("FileCreated","FileModified","FileRenamed")
    | where FileName =~ "litellm_init.pth"
    | project DeviceId, DeviceName, Timestamp, Evidence="PTH", Detail=strcat(FolderPath, "/", FileName)
),
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where (FolderPath has "/tmp/" or FolderPath has "\\Temp\\")
    | where FileName in~ ("tpcp.tar.gz","session.key","payload.enc","session.key.enc","pglog",".pg_state")
    | project DeviceId, DeviceName, Timestamp, Evidence="STAGE", Detail=strcat(FolderPath, "/", FileName)
),
(
    DeviceNetworkEvents
    | where Timestamp >= ago(lookback)
    | where RemoteUrl contains "models.litellm.cloud" or RemoteUrl contains "checkmarx.zone"
    | project DeviceId, DeviceName, Timestamp, Evidence="C2", Detail=coalesce(RemoteUrl, RemoteIP)
),
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where (FileName =~ "sysmon.service" and FolderPath has "/.config/systemd/user/")
        or (FileName =~ "sysmon.py" and FolderPath has "/.config/sysmon/")
    | project DeviceId, DeviceName, Timestamp, Evidence="PERSIST", Detail=strcat(FolderPath, "/", FileName)
),
(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName =~ "systemctl" and ProcessCommandLine has "--user" and ProcessCommandLine has "sysmon"
    | project DeviceId, DeviceName, Timestamp, Evidence="PERSIST", Detail=ProcessCommandLine
);
evidence
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    PTH=countif(Evidence == "PTH"),
    STAGE=countif(Evidence == "STAGE"),
    C2=countif(Evidence == "C2"),
    PERSIST=countif(Evidence == "PERSIST"),
    Details=make_set(Detail, 30)
    by DeviceId, DeviceName, WindowStart=bin(Timestamp, 2h)
| where PTH > 0 and (STAGE > 0 or C2 > 0 or PERSIST > 0)
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
) on DeviceId
| project WindowStart, FirstSeen, LastSeen, DeviceName, OSPlatform, PTH, STAGE, C2, PERSIST, Details
| order by LastSeen desc
```

---

## Chain 3 — AKS follow-on activity: suspicious `node-setup-*` pod creation plus nearby secret access
**MITRE:** T1610, T1552.001

**Hypothesis**
Public reporting associated the campaign with suspicious Kubernetes follow-on behavior, especially `node-setup-*` pods in `kube-system`, privileged setup-style containers, and unusual secret access. If a compromised CI runner or workload pivoted into AKS, AKS audit logs should reflect either the static `node-setup-*` indicator or a suspicious pod creation pattern, plus nearby secret read activity.

**Scope**
Use only where AKS control-plane audit logs are enabled into Log Analytics / Sentinel. This query is deliberately narrower than generic AKS anomaly hunting.

**Expected outcome**
A shortlist of cluster principals, namespaces, and pod-creation events that warrant urgent Kubernetes triage and secret-rotation assessment.

```kusto
let lookback = 30d;
let suspiciousPods =
AKSAuditAdmin
| where TimeGenerated >= ago(lookback)
| where Verb in ("create","patch","update")
| extend ObjResource = tostring(ObjectRef.resource), Namespace = tostring(ObjectRef.namespace), ObjName = tostring(ObjectRef.name), UserName = tostring(User.username)
| where ObjResource =~ "pods"
| extend RequestText = tostring(RequestObject)
| where ObjName startswith "node-setup-"
    or RequestText contains "\"privileged\":true"
    or RequestText contains "\"hostPath\""
    or RequestText contains "alpine:latest"
    or RequestText contains "\"name\":\"setup\""
| project ClusterId=_ResourceId, PodEventTime=TimeGenerated, UserName, Namespace, ObjName, Verb, UserAgent, SourceIps, RequestText;
let secretReads =
AKSAudit
| where TimeGenerated >= ago(lookback)
| extend ObjResource = tostring(ObjectRef.resource), Namespace = tostring(ObjectRef.namespace), ObjName = tostring(ObjectRef.name), UserName = tostring(User.username)
| where ObjResource =~ "secrets"
| where Verb in ("get","list","watch")
| summarize SecretOps=count(), SecretNamespaces=make_set(Namespace, 20), SecretNames=make_set(ObjName, 20), Agents=make_set(UserAgent, 10) by ClusterId=_ResourceId, UserName, SecretWindow=bin(TimeGenerated, 1h);
suspiciousPods
| extend SecretWindow = bin(PodEventTime, 1h)
| join kind=leftouter secretReads on ClusterId, UserName, SecretWindow
| project PodEventTime, ClusterId, UserName, Namespace, ObjName, Verb, UserAgent, SourceIps, SecretOps, SecretNamespaces, SecretNames, RequestText
| order by PodEventTime desc
```

---

## Chain 4 — Endpoint compromise candidates with IOC-backed network plus local staging or persistence
**MITRE:** T1041, T1543.002, T1005

**Hypothesis**
IOC-based network hits are common but noisy on their own. If a device contacted a known campaign domain and also created staging artifacts or persistence files on the same day, the probability of a true-positive compromise rises sharply.

**Scope**
Best fit: a security operations center (SOC)-facing incident queue query when fewer results are needed than a plain IOC sweep.

**Expected outcome**
A practical list of devices where network IOC hits are corroborated by stronger local evidence.

```kusto
let lookback = 30d;
let net =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemoteUrl contains "models.litellm.cloud" or RemoteUrl contains "checkmarx.zone"
| summarize NetFirst=min(Timestamp), NetLast=max(Timestamp), Domains=make_set(RemoteUrl, 10) by DeviceId, DeviceName, Day=bin(Timestamp, 1d);
let local =
union
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where (FolderPath has "/tmp/" or FolderPath has "\\Temp\\")
    | where FileName in~ ("tpcp.tar.gz","session.key","payload.enc","session.key.enc","pglog",".pg_state")
    | project DeviceId, DeviceName, Timestamp, Detail=strcat(FolderPath, "/", FileName), LocalType="StageArtifact"
),
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where (FileName =~ "sysmon.service" and FolderPath has "/.config/systemd/user/")
        or (FileName =~ "sysmon.py" and FolderPath has "/.config/sysmon/")
    | project DeviceId, DeviceName, Timestamp, Detail=strcat(FolderPath, "/", FileName), LocalType="PersistenceArtifact"
),
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where FileName =~ "litellm_init.pth"
    | project DeviceId, DeviceName, Timestamp, Detail=strcat(FolderPath, "/", FileName), LocalType="PTHDrop"
)
| summarize LocalFirst=min(Timestamp), LocalLast=max(Timestamp), LocalTypes=make_set(LocalType, 10), LocalDetails=make_set(Detail, 20) by DeviceId, DeviceName, Day=bin(Timestamp, 1d);
net
| join kind=inner local on DeviceId, DeviceName, Day
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
) on DeviceId
| project Day, DeviceName, OSPlatform, NetFirst, NetLast, Domains, LocalFirst, LocalLast, LocalTypes, LocalDetails
| order by Day desc, DeviceName asc
```

---

## Tuning notes
- In environments that legitimately use many `.pth` files, keeping Atomic 2 as-is for `litellm_init.pth` and using Chain 2 is safer than broadening the logic too early.
- If `RemoteUrl` population is weak, `RemoteIP` correlation is the next adjustment after resolving known campaign infrastructure into the local TI store.
- If Linux file-event coverage is partial, the value of Atomic 6 and Chain 1 rises.
- For Sentinel analytics rules, the chain queries can be converted into scheduled analytics and tuned on `Score`, `EvidenceCount`, or minimum evidence combinations.

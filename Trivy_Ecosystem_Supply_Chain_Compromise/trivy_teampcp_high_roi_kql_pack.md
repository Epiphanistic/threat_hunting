
# Trivy / TeamPCP / CanisterWorm — High-ROI KQL Pack
Date: 2026-03-30
Target platform: Microsoft Defender XDR Advanced Hunting and Microsoft Sentinel with Defender for Endpoint tables

## Scoping note

The Trivy hunt, the OSINT report, and the surrounding TeamPCP and CanisterWorm reporting overlap in places. This pack keeps the behaviors that recur across that material and that are practical to hunt in Microsoft endpoint telemetry:

- GitHub Actions runner process enumeration and procfs secret theft (`Runner.Worker`, `/proc/*/{mem,maps,environ}`)
- `curl | bash` / fetch-and-exec behavior from attacker-controlled infrastructure
- outbound traffic to `scan.aquasecurtiy.org`, `hackmoltrepeat.com`, and `*.raw.icp0.io`
- user-level persistence under `~/.config/systemd/user/pgmon.service` and `~/.local/share/pgmon/`
- local staging artifacts such as `tpcp.tar.gz`, `payload.enc`, and `/tmp/pglog`

Lower-confidence pivots from the aggregated indicator set, including the truncated `...y.org`, generic `api.github.com`, and the fallback IP, are not promoted to primary detections in this pack.

## Telemetry assumptions

These queries assume the following tables are available:

- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`
- `DeviceInfo`

Native endpoint tables are usually not enough on their own to recover exact GitHub Actions job names, workflow IDs, or StepSecurity run context. Use these queries to identify suspicious hosts or runners first, then pivot to CI audit logs, proxy logs, or StepSecurity telemetry.

---

# 1) Fast atomic detections by technique

## Atomic 1 — Fetch-and-exec from campaign infrastructure
**ATT&CK:** T1059.004, T1059.006, T1105

**Hypothesis**  
If the campaign executed its initial payload in runner or developer contexts, we should see shell, curl, or Python execution referencing attacker delivery infrastructure and common fetch-and-exec patterns such as `curl -sSfL ... | bash`.

**Scope**  
Linux endpoints and runners with process creation telemetry. High-value for GitHub Actions runners, self-hosted runners, developer workstations, and build agents.

**Expected outcome**  
A short candidate list of devices where command lines explicitly reference campaign delivery infrastructure or shell-pipe execution. This is a high-confidence starting point for triage.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where DeviceId in (LinuxDevices)
| where FileName in~ ("bash","sh","curl","wget","python","python3","sudo")
| extend Cmd = tostring(ProcessCommandLine),
         ParentCmd = tostring(InitiatingProcessCommandLine)
| where Cmd has_any ("hackmoltrepeat.com","scan.aquasecurtiy.org","raw.icp0.io","/moult","/molt","curl -sSfL","| bash")
    or ParentCmd has_any ("hackmoltrepeat.com","scan.aquasecurtiy.org","raw.icp0.io","/moult","/molt","curl -sSfL","| bash")
| project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Atomic 2 — Procfs secret theft against GitHub runner processes
**ATT&CK:** T1003.007, T1552

**Hypothesis**  
If the runner secret-theft path executed, we should observe process command lines that touch `/proc/<pid>/mem`, `/proc/<pid>/maps`, or `/proc/<pid>/environ`, often near references to `Runner.Worker`, `Runner.Listener`, `runsvc`, or `run.sh`.

**Scope**  
Linux runners and CI hosts. Best fit for GitHub-hosted or self-hosted runners and short-lived build agents.

**Expected outcome**  
Very small result volume. Any hit on a runner is suspicious until proven otherwise.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where DeviceId in (LinuxDevices)
| extend Cmd = tostring(ProcessCommandLine)
| where (Cmd has "/proc/" and Cmd has_any ("/mem","/maps","/environ"))
    or (Cmd has_any ("Runner.Worker","Runner.Listener","runsvc","run.sh") and Cmd has_any ("/proc/","isSecret"))
| project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Atomic 3 — GitHub runner process discovery prior to theft
**ATT&CK:** T1057

**Hypothesis**  
If the implant or injected step is preparing for procfs theft, it commonly discovers runner processes first. We should see `ps`, `pgrep`, `pidof`, or similar process-enumeration commands referencing `Runner.Worker`, `Runner.Listener`, `runsvc`, or `run.sh`.

**Scope**  
Linux runners and automation hosts with process telemetry.

**Expected outcome**  
Small result set. Standalone hits can still be benign on self-hosted runners, but they become materially stronger when followed by procfs access or suspicious network egress.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where DeviceId in (LinuxDevices)
| where FileName in~ ("bash","sh","ps","pgrep","pidof","grep","awk","sed","python","python3")
| extend Cmd = tostring(ProcessCommandLine)
| where Cmd has_any ("Runner.Worker","Runner.Listener","runsvc","run.sh")
| where Cmd has_any ("ps ","pgrep","pidof","grep ","/proc/")
| project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Atomic 4 — User-level systemd persistence and pgmon storage
**ATT&CK:** T1543.002

**Hypothesis**  
If the postinstall or follow-on persistence path executed, we should see creation of `pgmon.service`, files under `~/.config/systemd/user/`, or storage under `~/.local/share/pgmon/`, often near `systemctl --user` commands.

**Scope**  
Linux developer workstations, build agents, package-build hosts, and self-hosted runners.

**Expected outcome**  
Actionable persistence hits. These are strong containment pivots because they imply the host has moved beyond transient execution.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;

let file_hits =
    DeviceFileEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where FileName in~ ("pgmon.service","pglog","sysmon.py")
        or FolderPath has_any ("/.config/systemd/user","/.local/share/pgmon")
    | project Timestamp, DeviceName, DeviceId, SourceTable = "DeviceFileEvents",
              Match = strcat(FolderPath, "/", FileName),
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;

let proc_hits =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | extend Cmd = tostring(ProcessCommandLine)
    | where Cmd has "systemctl"
      and Cmd has "--user"
      and Cmd has_any ("pgmon.service","daemon-reload","enable","start","restart")
    | project Timestamp, DeviceName, DeviceId, SourceTable = "DeviceProcessEvents",
              Match = Cmd,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;

union file_hits, proc_hits
| order by Timestamp desc
```

---

## Atomic 5 — Python downloader / ICP polling / `/tmp/pglog`
**ATT&CK:** T1105, T1071.001

**Hypothesis**  
If the follow-on downloader stage ran, we should see Python-initiated outbound connections to `*.raw.icp0.io`, especially the specific `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` host, or local command lines referencing `/tmp/pglog`.

**Scope**  
Linux hosts with network and process telemetry.

**Expected outcome**  
Low-volume hits that indicate downloader or command-and-control behavior rather than simple package installation.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(timeframe)
| where DeviceId in (LinuxDevices)
| where RemoteUrl has_any ("tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io","raw.icp0.io")
| where InitiatingProcessFileName in~ ("python","python3","bash","sh")
   or InitiatingProcessCommandLine has_any ("/tmp/pglog","pgmon","raw.icp0.io")
| project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Atomic 6 — Network IoCs with suspicious process context
**ATT&CK:** T1071.001, T1041

**Hypothesis**  
If exfiltration or command-and-control (C2) occurred, suspicious Linux processes such as `curl`, `bash`, `python`, or Trivy-related runner processes should connect to campaign infrastructure such as `scan.aquasecurtiy.org`, `hackmoltrepeat.com`, or the GitHub uploads fallback.

**Scope**  
Linux endpoints / runners with network connection telemetry.

**Expected outcome**  
Medium-to-high confidence network hits. The presence of `uploads.github.com` is not malicious by itself, so it becomes important only with suspicious process context.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(timeframe)
| where DeviceId in (LinuxDevices)
| where RemoteUrl has_any ("scan.aquasecurtiy.org","hackmoltrepeat.com","uploads.github.com","raw.icp0.io")
| where InitiatingProcessFileName in~ ("curl","bash","sh","python","python3","trivy","node","npm")
   or InitiatingProcessCommandLine has_any ("Runner.Worker","tpcp-docs","moult","molt","pgmon","trivy")
| project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Atomic 7 — Suspicious package install of named CanisterWorm packages
**ATT&CK:** T1195.001, T1059.006

**Hypothesis**  
If the package-compromise branch of the campaign reached a development host, we may see `npm` / `pnpm` / `yarn` / `node` command lines referencing named package versions from the incident indicator set.

**Scope**  
Developer workstations, package-build systems, and self-hosted Linux runners with package-manager telemetry.

**Expected outcome**  
Low-to-moderate result volume depending on environment size. Useful for scoping, then confirm with persistence and network queries.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;
let badPackages = dynamic([
    "@teale.io/eslint-config@1.8.10",
    "@teale.io/eslint-config@1.8.13",
    "@teale.io/eslint-config@1.8.14",
    "@teale.io/eslint-config@1.8.15"
]);
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where DeviceId in (LinuxDevices)
| where FileName in~ ("npm","npx","pnpm","yarn","node")
| extend Cmd = tostring(ProcessCommandLine)
| where Cmd has_any (badPackages)
| project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

# 2) Complex behavioral chain queries backed by static indicators

## Chain 1 — GitHub Actions runner secret theft → staging → C2 / exfil
**ATT&CK:** T1057, T1003.007, T1552, T1041, T1567.002

**Hypothesis**  
If the runner-theft path succeeded, we should see a sequence on the same device:  
1. runner discovery or procfs access against `Runner.Worker` / `/proc/*/{mem,maps,environ}`  
2. local staging artifacts such as `tpcp.tar.gz` or `payload.enc`  
3. outbound traffic to `scan.aquasecurtiy.org`, `hackmoltrepeat.com`, or `uploads.github.com`

**Scope**  
Linux CI runners and build agents with process, file, and network telemetry.

**Expected outcome**  
A prioritized list of systems that show both behavioral chain evidence and static indicator reinforcement.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;

let proc_hits =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | extend Cmd = tostring(ProcessCommandLine)
    | where (Cmd has_any ("Runner.Worker","Runner.Listener","runsvc","run.sh") and Cmd has_any ("ps ","pgrep","pidof","/proc/"))
        or (Cmd has "/proc/" and Cmd has_any ("/mem","/maps","/environ"))
        or (FileName in~ ("python","python3","sudo","base64","bash","sh") and Cmd has_any ("base64","isSecret","Runner.Worker"))
    | project DeviceId, DeviceName, ProcTs = Timestamp, ProcFile = FileName, ProcCmd = Cmd;

let file_hits =
    DeviceFileEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where FileName in~ ("tpcp.tar.gz","payload.enc")
    | project DeviceId, FileTs = Timestamp, FileIndicator = strcat(FolderPath, "/", FileName);

let net_hits =
    DeviceNetworkEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where RemoteUrl has_any ("scan.aquasecurtiy.org","hackmoltrepeat.com","uploads.github.com")
    | project DeviceId, NetTs = Timestamp,
              RemoteIndicator = iff(isnotempty(RemoteUrl), RemoteUrl, RemoteIP),
              NetProc = InitiatingProcessFileName,
              NetCmd = InitiatingProcessCommandLine;

proc_hits
| join kind=innerunique net_hits on DeviceId
| where NetTs between (ProcTs .. ProcTs + 30m)
| join kind=leftouter file_hits on DeviceId
| where isnull(FileTs) or FileTs between (ProcTs - 5m .. NetTs + 10m)
| summarize FirstSeen = min(ProcTs),
            LastSeen = max(NetTs),
            SuspiciousProcesses = make_set(ProcFile, 20),
            SampleProcCommands = make_set(ProcCmd, 5),
            NetworkIoCs = make_set(RemoteIndicator, 20),
            StagingArtifacts = make_set(FileIndicator, 20),
            HitCount = count()
          by DeviceId, DeviceName
| order by LastSeen desc
```

---

## Chain 2 — Malicious package install / postinstall → Python → pgmon persistence → ICP polling
**ATT&CK:** T1195.001, T1059.006, T1543.002, T1105, T1071.001

**Hypothesis**  
If the package-compromise branch executed, the same device should show a package-install or postinstall context, followed by Python execution, then persistence artifacts (`pgmon.service`, `~/.local/share/pgmon/`), and optionally outbound traffic to `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` or another `raw.icp0.io` host.

**Scope**  
Linux developer systems, self-hosted runners, and package-build machines.

**Expected outcome**  
A narrow set of candidate hosts where the package compromise progressed from execution into persistence and network control.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;

let badPackages = dynamic([
    "@teale.io/eslint-config@1.8.10",
    "@teale.io/eslint-config@1.8.13",
    "@teale.io/eslint-config@1.8.14",
    "@teale.io/eslint-config@1.8.15"
]);

let install_hits =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where FileName in~ ("npm","npx","pnpm","yarn","node","bash","sh")
    | extend Cmd = tostring(ProcessCommandLine)
    | where Cmd has_any (badPackages) or Cmd has_any ("postinstall","node_modules",".pnpm","npm install","yarn add","pnpm add")
    | project DeviceId, DeviceName, InstallTs = Timestamp, InstallCmd = Cmd;

let py_hits =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where FileName in~ ("python","python3")
    | extend Cmd = tostring(ProcessCommandLine),
             ParentCmd = tostring(InitiatingProcessCommandLine)
    | where Cmd has_any ("pgmon","/tmp/pglog","raw.icp0.io")
        or ParentCmd has_any ("postinstall","node_modules","npm","pnpm","yarn")
    | project DeviceId, PyTs = Timestamp, PyCmd = Cmd;

let persist_hits =
    union isfuzzy=true
    (
        DeviceFileEvents
        | where Timestamp > ago(timeframe)
        | where DeviceId in (LinuxDevices)
        | where FileName in~ ("pgmon.service","pglog")
            or FolderPath has_any ("/.config/systemd/user","/.local/share/pgmon")
        | project DeviceId, PersistTs = Timestamp, PersistIndicator = strcat(FolderPath, "/", FileName)
    ),
    (
        DeviceProcessEvents
        | where Timestamp > ago(timeframe)
        | where DeviceId in (LinuxDevices)
        | extend Cmd = tostring(ProcessCommandLine)
        | where Cmd has "systemctl"
          and Cmd has "--user"
          and Cmd has_any ("pgmon.service","daemon-reload","enable","start","restart")
        | project DeviceId, PersistTs = Timestamp, PersistIndicator = Cmd
    );

let c2_hits =
    DeviceNetworkEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where RemoteUrl has_any ("tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io","raw.icp0.io")
    | project DeviceId, NetTs = Timestamp,
              C2Indicator = iff(isnotempty(RemoteUrl), RemoteUrl, RemoteIP),
              NetCmd = InitiatingProcessCommandLine;

install_hits
| join kind=innerunique py_hits on DeviceId
| where PyTs between (InstallTs .. InstallTs + 60m)
| join kind=leftouter persist_hits on DeviceId
| where isnull(PersistTs) or PersistTs between (InstallTs .. PyTs + 90m)
| join kind=leftouter c2_hits on DeviceId
| where isnull(NetTs) or NetTs between (PyTs .. PyTs + 90m)
| summarize FirstSeen = min(InstallTs),
            LastSeen = max(coalesce(NetTs, PersistTs, PyTs)),
            InstallEvidence = make_set(InstallCmd, 5),
            PythonEvidence = make_set(PyCmd, 5),
            PersistenceEvidence = make_set(PersistIndicator, 20),
            C2Evidence = make_set(C2Indicator, 20),
            HitCount = count()
          by DeviceId, DeviceName
| order by LastSeen desc
```

---

## Chain 3 — Credential collection paths → archive staging → exfil endpoint
**ATT&CK:** T1552.001, T1552.004, T1041

**Hypothesis**  
If local credential harvesting preceded exfiltration, we should observe command lines referencing SSH keys, SSH host keys, Docker/Kubernetes secret locations, or related secret-bearing paths, followed by staging artifacts and a near-term connection to `scan.aquasecurtiy.org` or the GitHub uploads fallback.

**Scope**  
Linux runners and developer systems with full process, file, and network telemetry.

**Expected outcome**  
Medium-to-high fidelity hits where static indicators reinforce a behavioral collection-and-exfiltration chain.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;

let collection_hits =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | extend Cmd = tostring(ProcessCommandLine)
    | where Cmd has_any ("/.ssh/id_rsa",
                         "/.ssh/id_ed25519",
                         "/.ssh/authorized_keys",
                         "/.ssh/config",
                         "/.ssh/known_hosts",
                         "/etc/ssh/ssh_host_",
                         "/.docker/config.json",
                         "/var/run/secrets/kubernetes.io")
    | where Cmd has_any ("cat ","cp ","tar ","gzip","zip","python","bash","sh","grep ")
    | project DeviceId, DeviceName, CollectTs = Timestamp, CollectCmd = Cmd;

let stage_hits =
    DeviceFileEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where FileName in~ ("tpcp.tar.gz","payload.enc")
    | project DeviceId, StageTs = Timestamp, StageIndicator = strcat(FolderPath, "/", FileName);

let exfil_hits =
    DeviceNetworkEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where RemoteUrl has_any ("scan.aquasecurtiy.org","uploads.github.com")
    | project DeviceId, ExfilTs = Timestamp,
              ExfilIndicator = iff(isnotempty(RemoteUrl), RemoteUrl, RemoteIP),
              NetCmd = InitiatingProcessCommandLine;

collection_hits
| join kind=innerunique exfil_hits on DeviceId
| where ExfilTs between (CollectTs .. CollectTs + 30m)
| join kind=leftouter stage_hits on DeviceId
| where isnull(StageTs) or StageTs between (CollectTs .. ExfilTs + 10m)
| summarize FirstSeen = min(CollectTs),
            LastSeen = max(ExfilTs),
            CollectionEvidence = make_set(CollectCmd, 10),
            StagingEvidence = make_set(StageIndicator, 20),
            ExfilEvidence = make_set(ExfilIndicator, 20),
            HitCount = count()
          by DeviceId, DeviceName
| order by LastSeen desc
```

---

## Chain 4 — Trivy / CI context → suspicious egress → runner theft behavior
**ATT&CK:** T1195.001, T1003.007, T1071.001, T1041

**Hypothesis**  
If the suspicious activity occurred specifically in a Trivy or CI execution context rather than as generic Linux activity, we should see a local process context that references `trivy`, `aquasecurity/trivy-action`, `get.trivy.dev`, or the compromised tag window (`0.69.4` / `0.69.5` / `0.69.6`), followed by suspicious network egress and ideally procfs theft behavior.

**Scope**  
Linux CI runners and build systems that execute Trivy or wrapper scripts around Trivy.

**Expected outcome**  
A short, high-priority list of runners where static campaign infrastructure overlaps with Trivy-specific execution context and post-download theft behavior.

```kusto
let timeframe = 30d;
let LinuxDevices =
    DeviceInfo
    | where Timestamp > ago(timeframe)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
    | where OSPlatform == "Linux"
    | project DeviceId;

let trivy_context =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | extend Cmd = tostring(ProcessCommandLine),
             ParentCmd = tostring(InitiatingProcessCommandLine)
    | where Cmd has_any ("trivy","aquasecurity/trivy-action","get.trivy.dev","0.69.4","0.69.5","0.69.6")
        or ParentCmd has_any ("trivy","aquasecurity/trivy-action","get.trivy.dev","0.69.4","0.69.5","0.69.6")
    | project DeviceId, DeviceName, CtxTs = Timestamp, CtxCmd = Cmd;

let suspicious_net =
    DeviceNetworkEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | where RemoteUrl has_any ("scan.aquasecurtiy.org","hackmoltrepeat.com","uploads.github.com")
    | project DeviceId, NetTs = Timestamp,
              NetIndicator = iff(isnotempty(RemoteUrl), RemoteUrl, RemoteIP),
              NetCmd = InitiatingProcessCommandLine;

let theft_hits =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where DeviceId in (LinuxDevices)
    | extend Cmd = tostring(ProcessCommandLine)
    | where (Cmd has "/proc/" and Cmd has_any ("/mem","/maps","/environ"))
        or Cmd has_any ("Runner.Worker","Runner.Listener","runsvc","run.sh","isSecret")
    | project DeviceId, TheftTs = Timestamp, TheftCmd = Cmd;

trivy_context
| join kind=innerunique suspicious_net on DeviceId
| where NetTs between (CtxTs - 5m .. CtxTs + 60m)
| join kind=leftouter theft_hits on DeviceId
| where isnull(TheftTs) or TheftTs between (CtxTs - 5m .. NetTs + 30m)
| summarize FirstSeen = min(CtxTs),
            LastSeen = max(NetTs),
            TrivyContext = make_set(CtxCmd, 10),
            NetworkEvidence = make_set(NetIndicator, 20),
            TheftEvidence = make_set(TheftCmd, 10),
            HitCount = count()
          by DeviceId, DeviceName
| order by LastSeen desc
```

---

# Operator guidance

## Run order
1. **Atomic 2** — procfs secret theft against runner processes  
2. **Atomic 4** — user-level systemd persistence and pgmon storage  
3. **Atomic 6** — network IoCs with suspicious process context  
4. **Chain 1** — runner secret theft → staging → C2 / exfil  
5. **Chain 2** — package/postinstall → persistence → ICP polling

## Why this order
- It prioritizes the most distinctive and least-benign behaviors first.
- It avoids over-weighting weak static IoCs.
- It gives you both fast scoping queries and higher-fidelity chain queries.

## Limitations
- Native endpoint telemetry usually cannot prove the exact GitHub workflow step or StepSecurity “analyze” row by itself.
- `uploads.github.com` can be benign in CI/CD. Treat it as suspicious only when correlated with `tpcp` / `tpcp-docs`, procfs theft, or staging artifacts.
- The source indicator bundle contains some weak or explicitly `FOR_REVIEW` pivots. This pack excludes those from primary logic unless they add correlation value.

## Next step
Use the atomic queries to identify suspect devices, then run the matching complex chain query against the reduced device set and pivot to proxy or CI audit logs for full incident reconstruction.

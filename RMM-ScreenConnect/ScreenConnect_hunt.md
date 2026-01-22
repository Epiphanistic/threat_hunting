 # ConnectWise ScreenConnect (Control) Misuse — Unauthorized Remote Access & Persistence

  ## Executive summary
  ConnectWise ScreenConnect (aka ConnectWise Control) is a legitimate RMM tool that adversaries abuse for covert
  interactive access, file transfer, and durable persistence. This hunt surfaces unauthorized use and suspicious relay
  infrastructure by correlating macOS download provenance (extended attributes), process execution, DNS/network, and
  persistence; Windows coverage tracks service/registry persistence, HostUrl parameters, DNS to risky relays, and
  install timelines. Linux telemetry is not instrumented in this hunt.

  ## Risk if true
  - Full remote control of endpoints (interactive sessions, clipboard, file transfer).
  - Persistence via “Access” clients enabling unattended access (macOS LaunchAgents/Daemons; Windows services/tasks/
  Run keys).
  - Credential access / data theft via live operator activity and staging/exfil over the remote session.
  - Lateral movement using existing user context and trust paths.

  ## Hypothesis
  Compromised or misused endpoints will show: (1) macOS download provenance/extended attributes with ScreenConnect query
  parameters (`h`, `p`, `i`, `e`, `y`, `n`, `a`); (2) subsequent ScreenConnect execution; (3) DNS/egress to non-vendor
  relays; (4) persistence (macOS LaunchAgents/Daemons; Windows services/tasks/Run keys); (5) behavior indicative of
  unattended access.

  ## Scope
  - In-scope: macOS and Windows endpoints with ScreenConnect/Control installers or clients on disk; execution telemetry
  referencing ScreenConnect; DNS/network tied to ScreenConnect processes; macOS extended attributes showing download
  provenance; persistence artefacts (LaunchAgents/Daemons, services/tasks/Run keys). Time windows anchored on first
  install, first run, first DNS/egress, and persistence creation.
  - Out-of-scope by default: sanctioned ScreenConnect deployments when relay infrastructure and provenance match
  approved sources (handled via allowlists and ownership checks).

  ## MITRE mapping
  - T1219 Remote Access Tools
  - T1105 Ingress Tool Transfer
  - T1071.004 Application Layer (DNS) for coordination/C2
  - T1547.011 Launch Agent (macOS persistence)
  - T1543.003 Create/Modify System Process (Windows services)
  - T1053 Scheduled Task/Job (Windows if used)
  - T1566 / T1204.002 (if delivered via user-run installers/social engineering)

  ## Data sources
  - EDR: process exec (path/cmdline/parent-child), file ops, network (dest IP/port/SNI), DNS (query/answers).
  - macOS provenance: extended attributes (`kMDItemWhereFroms`) and download metadata/quarantine flags.
  - Persistence: macOS LaunchAgents/Daemons inventory/events; Windows services creation/modification, scheduled tasks,
  Run keys.
  - Context: asset ownership, approved support tickets, proxy/firewall logs for relay reputation and egress validation.
  - Parameters to extract: ScreenConnect query-string keys (`h`, `p`, `i`, `e`, `y`, `n`, `a`) from macOS provenance or
  HostUrl/CommandLine fields.

  ## Expected outcome
  - Tiered outputs:
      (1) likely authorized (approved relays, expected paths, known IT owners);
      (2) suspicious/requires escalation (non-vendor relay, unusual provenance, persistence present);
      (3) confirmed malicious/abusive (operator behavior + suspicious relay + persistence + other compromise signals).
  - Deliverables: correlation from provenance → execution → DNS/network → persistence; relay-risk flagging for non-
  vendor hosts; host/user + first-seen timestamps + relay host/domain + persistence indicators + process tree summary.
  - Tuning: allowlist for vendor relays/sanctioned internal use; exclusions for lookalike enterprise tools; response
  guidance (validate user intent, collect artefacts, isolate if needed, remove persistence, rotate credentials if
  interactive compromise suspected).

  ## Logscale queries
  Moved to: [ScreenConnect Logscale queries](ScreenConnect_Logscale_queries.md)

  ## External discovery — example Censys pivot for suspicious ScreenConnect relays
  Moved to: [Censys pivot workflow](ScreenConnect_Censys_pivot.md)

  ## Triage and response tips
  - Validate relay hosts against allowlists; anything not vendor-approved is high priority.
  - Review provenance → execution → DNS timeline; short gaps between download and execution increase risk.
  - Confirm persistence presence (macOS plist names with `connectwisecontrol-*-(onlogin|prelogin)`, Windows services/
  tasks/Run keys) and whether aligned with sanctioned use.
  - For suspicious cases: capture artefacts, disable/quarantine host, remove persistence, rotate credentials, and check
  for lateral movement via session logs.
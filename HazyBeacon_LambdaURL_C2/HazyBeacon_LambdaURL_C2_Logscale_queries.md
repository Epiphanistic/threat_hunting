# Lambda URL Covert C2 - LogScale Queries

Queries below are copied from the dashboard YAML. Adjust allowlists and
paths to your environment as needed.

## Non browser DNS requests to lambda domains
```logscale
| in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| regex(field=DomainName, regex="\\b[0-9A-Za-z-]+\\.lambda-url\\.[a-z0-9-]+\\.on\\.aws\\b")
// unusual lolbin processes| in(field=ContextBaseFileName, values=["svchost.exe","services.exe","lsass.exe","winlogon.exe","csrss.exe","smss.exe","wininit.exe","spoolsv.exe","wmiapsrv.exe","msiexec.exe","taskhostw.exe","conhost.exe","rundll32.exe","dcomlaunch.exe","explorer.exe","werfault.exe","launchd","kernel_task","loginwindow","systemstats","securityd","opendirectoryd","installd","softwareupdated","distnoted","coreservicesd","systemd","init","kswapd0","kworker","pid1","dbus-daemon","sshd","cron","rsyslogd","networkd-dispatcher"])
| !regex(field=ContextBaseFileName,regex="(?i).*(chrome|msedge|Microsoft\ Edge|firefox|iexplore|opera|brave|chromium|safari|MsSense).*",strict=true)
| groupBy(
    [ContextBaseFileName],
    function=([
      count(aid, as=Connections_Count),
      min(ContextTimeStamp, as=FirstRequest),
      max(ContextTimeStamp, as=LastRequest),
      collect([DomainName,ComputerName,#repo,@rawstring], limit=20000)
    ])
  )
| FirstRequest := formatTime(format="%F %T.%L", field="FirstRequest")
| LastRequest  := formatTime(format="%F %T.%L", field="LastRequest")
```

## Detections on hosts with DNS requests to lambda
```logscale
ExternalApiType = Event_DetectionSummaryEvent
      | in(field=Severity, values=["1","2","3","4","5"])
      | detect_time:=ProcessStartTime
      | rawstring_detect:=@rawstring

| join({
        in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
        | regex(field=DomainName, regex="\\b[0-9A-Za-z-]+\\.lambda-url\\.[a-z0-9-]+\\.on\\.aws\\b")
        // unusual lolbin processes| in(field=ContextBaseFileName, values=["svchost.exe","services.exe","lsass.exe","winlogon.exe","csrss.exe","smss.exe","wininit.exe","spoolsv.exe","wmiapsrv.exe","msiexec.exe","taskhostw.exe","conhost.exe","rundll32.exe","dcomlaunch.exe","explorer.exe","werfault.exe","launchd","kernel_task","loginwindow","systemstats","securityd","opendirectoryd","installd","softwareupdated","distnoted","coreservicesd","systemd","init","kswapd0","kworker","pid1","dbus-daemon","sshd","cron","rsyslogd","networkd-dispatcher"])
        | !regex(field=ContextBaseFileName,regex="(?i).*(chrome|msedge|Microsoft\ Edge|firefox|iexplore|opera|brave|chromium|safari|MsSense).*",strict=true)
        | rawstring_dns:=@rawstring
        | time_dns:=@timestamp
},field=[aid], key=[aid], include=[ContextBaseFileName,QueryStatus, DomainName,rawstring_dns,time_dns],mode=inner, max=20000)
| groupBy(
    [ContextBaseFileName, FileName, CommandLine,DomainName,IOCValue,SeverityName,DetectName,DetectDescription],
    function=([
      count(aid, as=Connections_Count),
      min(ContextTimeStamp, as=FirstRequest),
      max(ContextTimeStamp, as=LastRequest),
      collect([DomainName,ComputerName,#repo,rawstring_dns,rawstring_detect], limit=20000)
    ])
  )
| FirstRequest := formatTime(format="%F %T.%L", field="FirstRequest")
| LastRequest  := formatTime(format="%F %T.%L", field="LastRequest")
```

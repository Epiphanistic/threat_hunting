# AppSuite PDF Editor Backdoor - LogScale Queries
These queries are untested in your environment and are provided as guidance/examples. Validate and tune before operational use.


Queries below are copied from the dashboard YAML. Use the dashboard time
ranges as a guide (some widgets use 1d/7d/1y windows).

## DNS to all confirmed domains (short window)
```logscale
in(field=#event_simpleName,values=["DnsRequest","SuspiciousDnsRequest"])
| in(field=DomainName, values=["download*.internetdownloadhub.biz","download*.masterlifemastermind.net","download*.pdfgj.com","download*.apdft.online",
"pdf-kiosk.com","pdf-kiosk.net","easyonestartpdf.com","ltdpdf.net","fileconverterdownload.com","pdfworker.com",
"getsmartpdf.com","proonestartpdf.com","proonestarthub.com","pdfonestarthub.com","pdfonestarttoday.com",
"smartonestartpdf.com","cdasynergy.net","pdfscraper.com","pdffacts.com","*appsuites.ai","pdf-tool.appsuites.ai",
"vault.appsuites.ai","sdk.appsuites.ai","on.appsuites.ai","inst.productivity-tools.ai",
"pdfts.site","micromacrotechbase.com","pdfartisan.com","apdft.com","apdft.online","itpdf.net","itpdf.com",
"9mdp5f.com","advancedtransmitart.net","click4pdf.com","convertpdfplus.com","onestartbrowser.com","smartmanualspdf.com",
"transmitcdnzion.com","y2iax5.com","abf26u.com","mka3e8.com","5b7crp.com","pdfmeta.com","pdfreplace.com"])
| groupBy([DomainName,#repo], function=([count(aid, as=EventsCount, distinct=true), min(ContextTimeStamp, as=FirstEvent), max(ContextTimeStamp, as=LastEvent), collect([ComputerName,aid,ContextBaseFileName,ContextProcessId, QueryStatus], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Tracker for any commands executed via string PDF Editor.exe
```logscale
//Tracker for any commands executed via string PDF Editor.exe
CommandLine=/.*\\PDFEditor\\PDF\ Editor.exe*./i
| in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2","ProcessBlocked"])
| groupBy([#repo,ComputerName,aid], function=([count(aid, as=EventsCount), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([#event_simpleName,SHA256HashData,TargetProcessId,@rawstring], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
| sort(field=FirstEvent,order=asc)
```

## Tracker detections related to PDF Editor.exe file
```logscale
regex(field=ExternalApiType, regex="(?i)detect")
| FileName = "PDF Editor.exe"
| groupBy([ComputerName,aid], function=([count(aid, as=EventsCount), min(ProcessStartTime, as=FirstEvent), max(ProcessStartTime, as=LastEvent), collect([ProcessStartTime,SeverityName,DetectDescription,PatternDispositionDescription,ProcessId,FalconHostLink], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
| ProcessStartTime:=formatTime(format="%F %T.%L", field="ProcessStartTime")
```

## All hosts with processes by "PDF Editor.exe"
```logscale
CommandLine=/.*\\PDFEditor\\PDF\ Editor.exe*./i
| in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2","ProcessBlocked"])
| groupBy([#repo,ComputerName,aid], function=([count(aid, as=EventsCount), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([#event_simpleName,SHA256HashData], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
| sort(field=FirstEvent,order=asc)
```

## Per-host commands enabling stealer/backdoor and staging data for exfil
```logscale
// setTimeInterval(start="1748736000000")
| regex(field=CommandLine, regex="(?i)--cm=--fullupdate")
| groupBy([#repo,ComputerName,aid], function=([count(aid, as=EventsCount), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([ExternalApiType,#event_simpleName,TargetProcessId,ProcessId,@rawstring], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Exfil stage processes by host
```logscale
//setTimeInterval(start="1748736000000")
| regex(field=CommandLine, regex="(?i)--cm=--(backupupdate|ping)")
| groupBy([#repo,ComputerName,aid], function=([count(aid, as=EventsCount), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([#event_simpleName,ExternalApiType,@rawstring], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
| sort(field=FirstEvent,order=asc)
```

## Cleanup stage processes by host
```logscale
// setTimeInterval(start="1748736000000")
| regex(field=CommandLine, regex="(?i)--cm=--cleanup")
| groupBy([#repo,ComputerName,aid], function=([count(aid, as=EventsCount), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([ExternalApiType,#event_simpleName,TargetProcessId,ProcessId,@rawstring], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS requests to exfil or update subdomains with detections
```logscale
//setTimeInterval(start="1748736000000")
| in(field=#event_simpleName,values=["DnsRequest","SuspiciousDnsRequest"])
| in(field=DomainName, values=["vault.appsuites.ai", "inst.productivity-tools.ai"])
| join({
(ExternalApiType = "Event_DetectionSummaryEvent" and (@rawstring=/.*appsuites\.ai*./i or @rawstring=/.*\\PDF\ Editor.exe*./i))
| detect_timestamp:=ProcessStartTime
}, field=[aid], key=[aid], include=[detect_timestamp,FalconHostLink,SeverityName,DetectName,DetectDescription,PatternDispositionDescription,ProcessId],mode=left, max=20000)
| groupBy([ComputerName,aid], function=([count(aid, as=EventsCount), min(ContextTimeStamp, as=FirstEvent), max(ContextTimeStamp, as=LastEvent), collect([ContextBaseFileName,ContextProcessId,detect_timestamp,FalconHostLink,SeverityName,DetectName,DetectDescription,PatternDispositionDescription,ProcessId], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
| detect_timestamp:=formatTime(format="%F %T.%L", field="detect_timestamp")
```

## DNS requests to exfil or update subdomains
```logscale
in(field=#event_simpleName,values=["DnsRequest",SuspiciousDnsRequest])
| in(field=DomainName, values=["vault.appsuites.ai", "inst.productivity-tools.ai"])
| groupBy([ComputerName,aid], function=([count(aid, as=EventsCount), min(ContextTimeStamp, as=FirstEvent), max(ContextTimeStamp, as=LastEvent), collect([ContextProcessId, QueryStatus,@rawstring], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS to all confirmed domains (long window)
```logscale
in(field=#event_simpleName,values=["DnsRequest","SuspiciousDnsRequest"])
| in(field=DomainName, values=["download*.internetdownloadhub.biz","download*.masterlifemastermind.net","download*.pdfgj.com","download*.apdft.online",
"pdf-kiosk.com","pdf-kiosk.net","easyonestartpdf.com","ltdpdf.net","fileconverterdownload.com","pdfworker.com",
"getsmartpdf.com","proonestartpdf.com","proonestarthub.com","pdfonestarthub.com","pdfonestarttoday.com",
"smartonestartpdf.com","cdasynergy.net","pdfscraper.com","pdffacts.com","*appsuites.ai","pdf-tool.appsuites.ai",
"vault.appsuites.ai","sdk.appsuites.ai","on.appsuites.ai","inst.productivity-tools.ai",
"pdfts.site","micromacrotechbase.com","pdfartisan.com","apdft.com","apdft.online","itpdf.net","itpdf.com",
"9mdp5f.com","advancedtransmitart.net","click4pdf.com","convertpdfplus.com","onestartbrowser.com","smartmanualspdf.com",
"transmitcdnzion.com","y2iax5.com","abf26u.com","mka3e8.com","5b7crp.com","pdfmeta.com","pdfreplace.com"])
| groupBy([DomainName,#repo], function=([count(aid, as=EventsCount, distinct=true), min(ContextTimeStamp, as=FirstEvent), max(ContextTimeStamp, as=LastEvent), collect([ComputerName,aid,ContextBaseFileName,ContextProcessId, QueryStatus], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

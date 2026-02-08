# DLL Sideloading Campaign abusing ahost.exe - LogScale Queries
These queries are untested in your environment and are provided as guidance/examples. Validate and tune before operational use.

## Suspicious `ahost.exe` execution from user-writable paths
```logscale
in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2"]) event_platform=Win
| regex(field=ImageFileName, regex="\\\\ahost\.exe$", flags="Fi")
| regex(field=CommandLine, regex="(\\\\Users\\\\|AppData|Temp|Downloads|ProgramData)", flags="Fi")
| case {
  ProcessStartTime=* | EventTime:=ProcessStartTime;
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([ComputerName,aid,#repo], function=([count(aid, as=EventsCount), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([ImageFileName,CommandLine,ParentImageFileName,ParentCommandLine,UserName], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## `libcares-2.dll` evidence associated with `ahost.exe`
```logscale
in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2","FileWritten","PeFileWritten","FileDetectInfo"]) event_platform=Win
| (regex(field=ImageFileName, regex="\\\\ahost\.exe$", flags="Fi") or regex(field=ContextBaseFileName, regex="\\\\ahost\.exe$", flags="Fi"))
| (
    regex(field=TargetFileName, regex="\\\\libcares-2\.dll$", flags="Fi")
    or regex(field=FileName, regex="^libcares-2\.dll$", flags="Fi")
    or regex(field=CommandLine, regex="libcares-2\.dll", flags="Fi")
    or regex(field=@rawstring, regex="libcares-2\.dll", flags="Fi")
  )
| case {
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  ProcessStartTime=* | EventTime:=ProcessStartTime;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([ComputerName,aid,#repo], function=([count(aid, as=EventsCount), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([#event_simpleName,ImageFileName,ContextBaseFileName,TargetFileName,FileName,CommandLine,SHA256HashData,MD5HashData], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Chain correlation: `ahost.exe` plus `libcares-2.dll` on same host within 10 minutes
```logscale
correlate(
  AHOST: {
    in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2"]) event_platform=Win
    | regex(field=ImageFileName, regex="\\\\ahost\.exe$", flags="Fi")
  } include:[aid,ComputerName,#repo,ImageFileName,CommandLine,ParentImageFileName,ProcessStartTime,ContextTimeStamp,timestamp],

  LIB: {
    in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2","FileWritten","PeFileWritten","FileDetectInfo"]) event_platform=Win
    | (
        regex(field=TargetFileName, regex="\\\\libcares-2\.dll$", flags="Fi")
        or regex(field=FileName, regex="^libcares-2\.dll$", flags="Fi")
        or regex(field=CommandLine, regex="libcares-2\.dll", flags="Fi")
        or regex(field=@rawstring, regex="libcares-2\.dll", flags="Fi")
      )
  } include:[aid,ComputerName,#repo,TargetFileName,FileName,ImageFileName,CommandLine,ContextTimeStamp,ProcessStartTime,timestamp],

  sequence=false, within=10m, globalConstraints=[aid,ComputerName]
)
| case {
  AHOST.ProcessStartTime=* | AhostEventTime:=AHOST.ProcessStartTime;
  AHOST.ContextTimeStamp=* | AhostEventTime:=AHOST.ContextTimeStamp;
  AHOST.timestamp=* | AhostEventTime:=AHOST.timestamp;
}
| case {
  LIB.ContextTimeStamp=* | LibEventTime:=LIB.ContextTimeStamp;
  LIB.ProcessStartTime=* | LibEventTime:=LIB.ProcessStartTime;
  LIB.timestamp=* | LibEventTime:=LIB.timestamp;
}
| groupBy([AHOST.ComputerName,AHOST.aid,AHOST.#repo], function=([count(AHOST.aid, as=EventsCount), min(AhostEventTime, as=FirstAhostEvent), max(AhostEventTime, as=LastAhostEvent), min(LibEventTime, as=FirstLibEvent), max(LibEventTime, as=LastLibEvent), collect([AHOST.ImageFileName,AHOST.CommandLine,AHOST.ParentImageFileName,LIB.TargetFileName,LIB.FileName,LIB.ImageFileName,LIB.CommandLine,AhostEventTime,LibEventTime], limit=20000)]))
| FirstEvent:=FirstAhostEvent
| case { FirstLibEvent=* | FirstEvent:=FirstLibEvent; }
| LastEvent:=LastAhostEvent
| case { LastLibEvent=* | LastEvent:=LastLibEvent; }
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## `AddInProcess32.exe` launches with suspicious parent lineage
```logscale
in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2"]) event_platform=Win
| regex(field=ImageFileName, regex="\\\\AddInProcess32\.exe$", flags="Fi")
| (regex(field=ParentImageFileName, regex="\\\\ahost\.exe$", flags="Fi") or regex(field=ParentCommandLine, regex="ahost\.exe", flags="Fi"))
| case {
  ProcessStartTime=* | EventTime:=ProcessStartTime;
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([ComputerName,aid,#repo], function=([count(aid, as=EventsCount), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([ImageFileName,CommandLine,ParentImageFileName,ParentCommandLine,SHA256HashData], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## High-risk file writes for campaign filenames
```logscale
in(field=#event_simpleName, values=["FileWritten","PeFileWritten","FileDetectInfo","CriticalFileModified"]) event_platform=Win
| in(field=FileName, values=["ahost.exe","libcares-2.dll","AddInProcess32.exe"])
| regex(field=TargetFileName, regex="(?i)(\\\\Users\\\\|AppData|Temp|Downloads|ProgramData)", flags="Fi")
| case {
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([ComputerName,aid,#repo,FileName], function=([count(aid, as=EventsCount), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([TargetFileName,FilePath,SHA256HashData,MD5HashData,ContextBaseFileName,ContextProcessId], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Known campaign hash matches
```logscale
in(field=#event_simpleName, values=["FileWritten","PeFileWritten","FileDetectInfo","ProcessRollup2","SyntheticProcessRollup2"])
| (
    in(field=SHA256HashData, values=[
      "7c41ac7b5bf15e34d50d6abbe28254e94e6c21e0ccab9fa68aca05049a515758",
      "e7be7413c4cff8595de4cbc9c8621163565afe3e57412e59be3389aef1a18cc5",
      "0b7660173e0bfe2ff7015014d5c7cc1f27e9e80c330f5553316f5c031b387d15",
      "a7d7965baed40cfd0edbc9d7ef3052dcf20148769b2dfe32d0117dbd762b8a9d",
      "791a7d2710409cf72cf34bd4c29a3ebfe17ad3217d138215c0e03aa3513c8d0e",
      "e533da586b912241cc8c5d4762d78607b50b75cb7070ad839d72f8ee76cb5636"
    ])
    or MD5HashData="fd3c8166e7fbbb64d12c1170b8f4bacf"
  )
| case {
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  ProcessStartTime=* | EventTime:=ProcessStartTime;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([ComputerName,aid,#repo,SHA256HashData,MD5HashData], function=([count(aid, as=EventsCount), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([#event_simpleName,FileName,TargetFileName,ImageFileName,CommandLine], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS to campaign domain and broader Duck DNS pivots
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| (DomainName="dgflex.duckdns.org" or regex(field=DomainName, regex="\\.duckdns\\.org$", flags="Fi"))
| case {
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([DomainName,#repo], function=([count(aid, as=EventsCount, distinct=true), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([ComputerName,aid,ContextBaseFileName,ContextProcessId,QueryStatus], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS from likely chain processes
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| regex(field=ContextBaseFileName, regex="(?i)^(ahost|AddInProcess32)\.exe$", flags="Fi")
| case {
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([ComputerName,aid,#repo], function=([count(aid, as=EventsCount), count(DomainName, as=UniqueDomains, distinct=true), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([DomainName,ContextBaseFileName,ContextProcessId,QueryStatus], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Bypass-prone process usage in user-writable locations
```logscale
in(field=#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2"]) event_platform=Win
| regex(field=ImageFileName, regex="\\\\AddInProcess32\.exe$", flags="Fi")
| regex(field=ImageFileName, regex="(?i)(\\\\Users\\\\|AppData|Temp|Downloads)", flags="Fi")
| case {
  ProcessStartTime=* | EventTime:=ProcessStartTime;
  ContextTimeStamp=* | EventTime:=ContextTimeStamp;
  timestamp=* | EventTime:=timestamp;
}
| groupBy([ComputerName,aid,#repo], function=([count(aid, as=EventsCount), min(EventTime, as=FirstEvent), max(EventTime, as=LastEvent), collect([ImageFileName,CommandLine,ParentImageFileName,UserName], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

# Notepad++ WinGUp Hijack - LogScale Queries
These queries are untested in your environment and are provided as guidance/examples. Validate and tune before operational use.


Tune allowlists and field names to your schema.

## Exposure inventory: Notepad++ versions < 8.8.9
```logscale
// Inventory Notepad++ installs prior to 8.8.9
#event_simpleName="InstalledApplication"
| AppProductId="Notepad++"
| rawstring_InstalledApplication:=@rawstring
| regex(field=AppVersion, regex="^(?i)(?:[0-7](?:\\.\\d+(?:\\.\\d+)?)?|8(?:\\.(?:[0-7](?:\\.\\d+)?|8(?:\\.[0-8])?))?)$")
| in(field=UpdateFlag, values=["1","3"]) // 1=Enumerated, 3=Newly installed
| groupBy([#repo,ComputerName,aid,AppVersion], function=([
    count(aid, as=Events_count),
    min(InstallDate, as=First_InstallDate),
    max(InstallDate, as=Last_InstallDate),
    collect([AppPath,UserName,UpdateFlag,rawstring_InstalledApplication], limit=20000)
]))
| First_InstallDate:=formatTime(format="%F %T.%L", field="First_InstallDate")
| Last_InstallDate:=formatTime(format="%F %T.%L", field="Last_InstallDate")
```

## Installer writes by updater or Notepad++ (npp.*.exe/.msi)
```logscale
// Correlate vulnerable installs with installer writes
#event_simpleName="InstalledApplication"
| AppProductId="Notepad++"
| regex(field=AppVersion, regex="^(?i)(?:[0-7](?:\\.\\d+(?:\\.\\d+)?)?|8(?:\\.(?:[0-7](?:\\.\\d+)?|8(?:\\.[0-8])?))?)$")
| in(field=UpdateFlag, values=["1","3"])
| join({
    #event_simpleName="PeFileWritten"
    | "event_platform"=Win
    | IsOnRemovableDisk="0"
    | regex(field=TargetFileName, regex="(?i)^.*npp\\.(?<WrittenVersion>[0-9]+(?:\\.[0-9]+)*)[^\\/\\\\]*\\.(?:exe|msi)$", strict=true)
    | rawstring_PeFileWritten:=@rawstring
    // Challenge: verify ContextBaseFileName allowlist (GUP.exe / notepad++.exe / enterprise packaging tools)
  }, field=[aid,AppVersion], key=[aid,WrittenVersion], include=[TargetFileName,SHA256HashData,UserName,ContextBaseFileName,ContextTimeStamp,WrittenVersion,rawstring_PeFileWritten], mode=inner)
| groupBy([#repo,ComputerName,aid,AppVersion,WrittenVersion], function=([
    count(aid, as=Events_count),
    min(InstallDate, as=First_InstallDate),
    max(InstallDate, as=Last_InstallDate),
    collect([AppPath,TargetFileName,SHA256HashData,UserName,ContextBaseFileName,ContextTimeStamp], limit=20000)
]))
| First_InstallDate:=formatTime(format="%F %T.%L", field="First_InstallDate")
| Last_InstallDate:=formatTime(format="%F %T.%L", field="Last_InstallDate")
| ContextTimeStamp:=formatTime(format="%F %T.%L", field="ContextTimeStamp")
```

## Suspicious installer execution from Temp/AppData
```logscale
#event_simpleName="ProcessRollup2" and event_platform="Win"
| regex(field=ImageFileName, regex="(?i)^.*\\npp\\.[0-9]+(?:\\.[0-9]+)*.*\\.(?:exe|msi)$")
| regex(field=CommandLine, regex="(?i)\\\\(temp|appdata)\\\\")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=Events_count),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([ImageFileName,CommandLine,ParentBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Chrysalis loader chain: BluetoothService.exe + log.dll in %AppData%\Bluetooth
```logscale
// File presence: BluetoothService.exe or log.dll in AppData\Bluetooth
in(field=#event_simpleName, values=["PeFileWritten","FileWritten","FileDetectInfo","CriticalFileModified"])
| event_platform=Win
| regex(field=TargetFileName, regex="(?i)\\\\AppData\\\\.*\\\\Bluetooth\\\\(BluetoothService\\.exe|log\\.dll)$")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=EventsCount),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([TargetFileName,ContextBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Chrysalis loader chain: BluetoothService.exe execution from AppData\Bluetooth
```logscale
#event_simpleName="ProcessRollup2" and event_platform="Win"
| regex(field=ImageFileName, regex="(?i)\\\\AppData\\\\.*\\\\Bluetooth\\\\BluetoothService\\.exe$")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=Events_count),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([ImageFileName,CommandLine,ParentBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## AutoUpdater.exe execution in Temp (reported behavior, use as supporting signal)
```logscale
#event_simpleName="ProcessRollup2" and event_platform="Win"
| regex(field=ImageFileName, regex="(?i)^.*\\\\temp\\\\AutoUpdater\\.exe$")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=Events_count),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([ImageFileName,CommandLine,ParentBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## update.exe execution in Temp (reported behavior, use as supporting signal)
```logscale
#event_simpleName="ProcessRollup2" and event_platform="Win"
| regex(field=ImageFileName, regex="(?i)^.*\\\\temp\\\\update\\.exe$")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=Events_count),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([ImageFileName,CommandLine,ParentBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Recon command activity with suspicious parent (AutoUpdater/GUP/Notepad++)
```logscale
#event_simpleName="ProcessRollup2" and event_platform="Win"
| regex(field=ImageFileName, regex="(?i)\\\\(whoami|systeminfo|tasklist|netstat)\\.exe$")
| regex(field=ParentBaseFileName, regex="(?i)^(AutoUpdater|GUP|notepad\\+\\+|npp)\\.exe$")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=Events_count),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([ImageFileName,CommandLine,ParentBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS requests to Notepad++ update domain (optional correlation)
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| DomainName=/.*notepad-plus-plus\\.org$/i
| regex(field=ContextBaseFileName, regex="(?i)^(GUP|notepad\\+\\+|npp)\\.exe$")
| groupBy([DomainName,#repo], function=([
    count(aid, as=EventsCount, distinct=true),
    min(ContextTimeStamp, as=FirstEvent),
    max(ContextTimeStamp, as=LastEvent),
    collect([ComputerName,aid,ContextBaseFileName,ContextProcessId,QueryStatus], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## GUP.exe DNS to non-Notepad++/GitHub domains (reported as suspicious)
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| regex(field=ContextBaseFileName, regex="(?i)^GUP\\.exe$")
| not regex(field=DomainName, regex="(?i)(^|\\.)notepad-plus-plus\\.org$|(^|\\.)github\\.com$|(^|\\.)release-assets\\.githubusercontent\\.com$")
| groupBy([DomainName,#repo], function=([
    count(aid, as=EventsCount, distinct=true),
    min(ContextTimeStamp, as=FirstEvent),
    max(ContextTimeStamp, as=LastEvent),
    collect([ComputerName,aid,ContextBaseFileName,ContextProcessId,QueryStatus], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS requests to api.skycloudcenter.com (Chrysalis C2)
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| DomainName=/.*api\\.skycloudcenter\\.com$/i
| groupBy([DomainName,#repo], function=([
    count(aid, as=EventsCount, distinct=true),
    min(ContextTimeStamp, as=FirstEvent),
    max(ContextTimeStamp, as=LastEvent),
    collect([ComputerName,aid,ContextBaseFileName,ContextProcessId,QueryStatus], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS requests to api.wiresguard.com (reported loader C2)
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| DomainName=/.*api\\.wiresguard\\.com$/i
| groupBy([DomainName,#repo], function=([
    count(aid, as=EventsCount, distinct=true),
    min(ContextTimeStamp, as=FirstEvent),
    max(ContextTimeStamp, as=LastEvent),
    collect([ComputerName,aid,ContextBaseFileName,ContextProcessId,QueryStatus], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Reported loader/stager filenames on disk (supporting signal)
```logscale
in(field=#event_simpleName, values=["PeFileWritten","FileWritten","FileDetectInfo","CriticalFileModified"])
| event_platform=Win
| regex(field=TargetFileName, regex="(?i)\\\\(ConsoleApplication2\\.exe|s047t5g\\.exe|libtcc\\.dll|conf\\.c|u\\.bat|admin|loader1|loader2|uffhxpSy|3yzr31vk)$")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=EventsCount),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([TargetFileName,ContextBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## DNS requests to temp.sh (reported exfil endpoint, supporting signal)
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| DomainName=/.*temp\\.sh$/i
| groupBy([DomainName,#repo], function=([
    count(aid, as=EventsCount, distinct=true),
    min(ContextTimeStamp, as=FirstEvent),
    max(ContextTimeStamp, as=LastEvent),
    collect([ComputerName,aid,ContextBaseFileName,ContextProcessId,QueryStatus], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## curl.exe uploads to temp.sh (reported exfil behavior, supporting signal)
```logscale
#event_simpleName="ProcessRollup2" and event_platform="Win"
| regex(field=ImageFileName, regex="(?i)\\\\curl\\.exe$")
| regex(field=CommandLine, regex="(?i)temp\\.sh")
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=Events_count),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([ImageFileName,CommandLine,ParentBaseFileName,UserName,SHA256HashData,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## securityError.log writes (v8.9+ validation failures)
```logscale
in(field=#event_simpleName, values=["FileWritten","FileDetectInfo","CriticalFileModified"])
| TargetFileName=/.*\\\\Notepad\\+\\+\\\\log\\\\securityError\\.log$/i
| groupBy([#repo,ComputerName,aid], function=([
    count(aid, as=EventsCount),
    min(timestamp, as=FirstEvent),
    max(timestamp, as=LastEvent),
    collect([TargetFileName,ContextBaseFileName,UserName,@rawstring], limit=20000)
]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

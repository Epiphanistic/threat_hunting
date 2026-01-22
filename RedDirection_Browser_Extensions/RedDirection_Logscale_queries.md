# RedDirection Chrome/Edge Malicious Extensions - LogScale Queries

Queries below are taken from the dashboard YAML. The `dart-9697-cancer-unique_aid.csv` lookup is
used as an exclusion list for known hosts; replace or remove it if not available.

## Compromised Chrome/Edge extensions - last 1 year
```logscale
"#event_simpleName" = InstalledBrowserExtension
| BrowserExtensionStatusEnabled="1"
| in(field="BrowserExtensionId", values=["kgmeffmlnkfnjpgmdndccklfigfhajen","dpdibkjjgbaadnnjhkmmnenkmbnhpobj","gaiceihehajjahakcglkhmdbbdclbnlf","mlgbkfnjdmaoldgagamcnommbbnhfnhf","eckokfcjbjbgjifpcbdmengnabecdakp","mgbhdehiapbjamfgekfpebmhmnmcmemg","cbajickflblmpjodnjoldpiicfmecmif","pdbfcnhlobhoahcamoefbfodpmklgmjm","eokjikchkppnkdipbiggnmlkahcdkikp","ihbiedpeaicgipncdnnkikeehnjiddck","jjdajogomggcjifnjgkpghcijgkbcjdi","mmcnmppeeghenglmidpmjkaiamcacmgm","ojdkklpgpacpicaobnhankbalkkgaafp","lodeighbngipjjedfelnboplhgediclp","hkjagicdaogfgdifaklcgajmgefjllmd","gflkbgebojohihfnnplhbdakoipdbpdm","kpilmncnoafddjpnbhepaiilgkdcieaf","caibdnkmpnjhjdfnomfhijhmebigcelo"], ignoreCase=true)
| groupBy([BrowserName,BrowserExtensionName,BrowserExtensionVersion,ComputerName,#repo], function=([count(#event_simpleName, as=Events_Count), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([aid,UserName,UserSid,BrowserExtensionId], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## New hosts with compromised browser extensions
```logscale
"#event_simpleName" = InstalledBrowserExtension
| BrowserExtensionStatusEnabled="1"
| in(field="BrowserExtensionId", values=["kgmeffmlnkfnjpgmdndccklfigfhajen","dpdibkjjgbaadnnjhkmmnenkmbnhpobj","gaiceihehajjahakcglkhmdbbdclbnlf","mlgbkfnjdmaoldgagamcnommbbnhfnhf","eckokfcjbjbgjifpcbdmengnabecdakp","mgbhdehiapbjamfgekfpebmhmnmcmemg","cbajickflblmpjodnjoldpiicfmecmif","pdbfcnhlobhoahcamoefbfodpmklgmjm","eokjikchkppnkdipbiggnmlkahcdkikp","ihbiedpeaicgipncdnnkikeehnjiddck","jjdajogomggcjifnjgkpghcijgkbcjdi","mmcnmppeeghenglmidpmjkaiamcacmgm","ojdkklpgpacpicaobnhankbalkkgaafp","lodeighbngipjjedfelnboplhgediclp","hkjagicdaogfgdifaklcgajmgefjllmd","gflkbgebojohihfnnplhbdakoipdbpdm","kpilmncnoafddjpnbhepaiilgkdcieaf","caibdnkmpnjhjdfnomfhijhmebigcelo"], ignoreCase=true)
| not match(file="dart-9697-cancer-unique_aid.csv", column="aid", field=aid, ignoreCase=true)
| groupBy([BrowserName,BrowserExtensionName,BrowserExtensionVersion,ComputerName,#repo], function=([count(#event_simpleName, as=Events_Count), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([aid,UserName,UserSid,BrowserExtensionId], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Hosts with browsers enabled and detections on host in between enablement
```logscale
"#event_simpleName" = InstalledBrowserExtension
| BrowserExtensionStatusEnabled="1"
| in(field="BrowserExtensionId", values=["kgmeffmlnkfnjpgmdndccklfigfhajen","dpdibkjjgbaadnnjhkmmnenkmbnhpobj","gaiceihehajjahakcglkhmdbbdclbnlf","mlgbkfnjdmaoldgagamcnommbbnhfnhf","eckokfcjbjbgjifpcbdmengnabecdakp","mgbhdehiapbjamfgekfpebmhmnmcmemg","cbajickflblmpjodnjoldpiicfmecmif","pdbfcnhlobhoahcamoefbfodpmklgmjm","eokjikchkppnkdipbiggnmlkahcdkikp","ihbiedpeaicgipncdnnkikeehnjiddck","jjdajogomggcjifnjgkpghcijgkbcjdi","mmcnmppeeghenglmidpmjkaiamcacmgm","ojdkklpgpacpicaobnhankbalkkgaafp","lodeighbngipjjedfelnboplhgediclp","hkjagicdaogfgdifaklcgajmgefjllmd","gflkbgebojohihfnnplhbdakoipdbpdm","kpilmncnoafddjpnbhepaiilgkdcieaf","caibdnkmpnjhjdfnomfhijhmebigcelo"], ignoreCase=true)
| join(
  {
    #streamingApiEvent="Event_DetectionSummaryEvent"
    | match(file="dart-9697-cancer-unique_aid.csv", column="aid", field=aid, ignoreCase=true)
    | in(field=Severity, values=["1","2","3","4","5"])
    | rawstring_detect:=@rawstring
    | detect_timestamp:=timestamp
}, field=[aid], key=[aid], include=[detect_timestamp,FalconHostLink,SeverityName,DetectName,DetectDescription,rawstring_detect,PatternDispositionDescription], mode=inner, max=20000)
| parseTimestamp(field="detect_timestamp", format="yyyy-MM-dd'T'HH:mm:ssX", as="detect_ms", addErrors=false, caseSensitive=true, timezone="UTC", timezoneAs="@tz")

| groupBy([BrowserName,BrowserExtensionName,BrowserExtensionVersion,ComputerName,#repo,SeverityName,DetectDescription,PatternDispositionDescription,detect_timestamp,detect_ms], function=([count(#event_simpleName, as=Events_Count), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([aid,UserName,UserSid,BrowserExtensionId,FalconHostLink,rawstring_detect], limit=20000)]))

| test(detect_ms <= LastEvent)
| test(FirstEvent <= detect_ms)
```

## IoC domain hits
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| in(field=DomainName, values=["admitab.com","edmitab.com","click.videocontrolls.com","c.undiscord.com","click.darktheme.net","c.jermikro.com","c.untwitter.com","c.unyoutube.net","admitclick.net","addmitad.com","admiitad.com","abmitab.com","admitlink.net"])
| groupBy([ComputerName,aid,QueryStatus,#repo,ContextBaseFileName], function=([count(aid, as=Events_Count), min(ContextTimeStamp, as=First_Event), max(ContextTimeStamp, as=Last_Event), collect([@rawstring], limit=20000)]))
| First_Event:=formatTime(format="%F %T.%L", field="First_Event")
| Last_Event:=formatTime(format="%F %T.%L", field="Last_Event")
| sort(Last_Event, order=desc, limit=20000)
```

## IoC domain hits but no extension installed
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| in(field=DomainName, values=["admitab.com","edmitab.com","click.videocontrolls.com","c.undiscord.com","click.darktheme.net","c.jermikro.com","c.untwitter.com","c.unyoutube.net","admitclick.net","addmitad.com","admiitad.com","abmitab.com","admitlink.net"])
| rawstring_dns:=@rawstring
| ContextTimeStamp_dns:=ContextTimeStamp
| join(
    {
      "#event_simpleName" = InstalledBrowserExtension
      | BrowserExtensionStatusEnabled="1"
      | rawstring_browser_ext:=@rawstring
      | in(field="BrowserExtensionId", values=["kgmeffmlnkfnjpgmdndccklfigfhajen","dpdibkjjgbaadnnjhkmmnenkmbnhpobj","gaiceihehajjahakcglkhmdbbdclbnlf","mlgbkfnjdmaoldgagamcnommbbnhfnhf","eckokfcjbjbgjifpcbdmengnabecdakp","mgbhdehiapbjamfgekfpebmhmnmcmemg","cbajickflblmpjodnjoldpiicfmecmif","pdbfcnhlobhoahcamoefbfodpmklgmjm","eokjikchkppnkdipbiggnmlkahcdkikp","ihbiedpeaicgipncdnnkikeehnjiddck","jjdajogomggcjifnjgkpghcijgkbcjdi","mmcnmppeeghenglmidpmjkaiamcacmgm","ojdkklpgpacpicaobnhankbalkkgaafp","lodeighbngipjjedfelnboplhgediclp","hkjagicdaogfgdifaklcgajmgefjllmd","gflkbgebojohihfnnplhbdakoipdbpdm","kpilmncnoafddjpnbhepaiilgkdcieaf","caibdnkmpnjhjdfnomfhijhmebigcelo"], ignoreCase=true)
}, field=[aid], key=[aid], include=[BrowserName,BrowserExtensionName,BrowserExtensionVersion,ComputerName,rawstring_browser_ext], mode=left)
| groupBy([ComputerName,#repo,ContextBaseFileName,BrowserName,BrowserExtensionName,BrowserExtensionVersion,ComputerName], function=([count(aid, as=Events_Count), min(ContextTimeStamp_dns, as=First_Event), max(ContextTimeStamp_dns, as=Last_Event)]), limit=20000)
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
| BrowserExtensionName="" or BrowserExtensionName!=*
```

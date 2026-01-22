# Silk Typhoon / UNC5221 - LogScale Queries

Adjust allowlists and paths to your environment as needed.

## [DE,C2,Exfiltration] Using Cloudflare Workers and Heroku app as communication to first tier C2
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| QueryStatus!="123"
| regex(field=DomainName, regex="(?:\\.herokudns\\.com|\\.herokuapp\\.com|\\.workers\\.dev)\\.?$", flags="Fi", strict=true)
| !regex(field=DomainName, regex="(?:firehose-tester\\.herokuapp\\.com)\\.?$", flags="Fi", strict=true)
// cut browsers/webviews
| not regex(field=ContextBaseFileName, regex="\\b(?:chrome|chromium|msedge|firefox|safari)(?:\\.exe)?\\b", flags="Fi", strict=true)
| not regex(field=ContextBaseFileName, regex="\\b(?:brave|opera|vivaldi|msedgewebview2|WebKit|Microsoft\ Edge\ Helper)\\b", flags="Fi", strict=true)
| groupBy([ComputerName, aid,#repo], function=([count(aid, as=Connections_Count), min(ContextTimeStamp, as=FirstRquest), max(ContextTimeStamp, as=LastRequest), count(DomainName, as=UniqueDomainCount,distinct=true),collect([ContextBaseFileName,DomainName], limit=20000)]))
| FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
| LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")
```

## [IA]Possible dl Brickstorm via quick or normal cloudflare tunnels
```logscale
in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
| DomainName=/\.trycloudflare.com/i or DomainName=/cfargotunnel/i
| not regex(field=ContextBaseFileName, regex="\\b(?:chrome|chromium|msedge|firefox|safari)(?:\\.exe)?\\b", flags="Fi", strict=true)
| not regex(field=ContextBaseFileName, regex="\\b(?:brave|opera|vivaldi|msedgewebview2|WebKit|Microsoft\ Edge\ Helper)\\b", flags="Fi", strict=true)
| join({
        #event_simpleName=DnsRequest
    
    | QueryStatus!="123"
    | regex(field=DomainName, regex="(?:\\.herokudns\\.com|\\.herokuapp\\.com|\\.workers\\.dev)\\.?$", flags="Fi", strict=true)
    // cut browsers/webviews
    | not regex(field=ContextBaseFileName, regex="\\b(?:chrome|chromium|msedge|firefox|safari)(?:\\.exe)?\\b", flags="Fi", strict=true)
    | not regex(field=ContextBaseFileName, regex="\\b(?:brave|opera|vivaldi|msedgewebview2|WebKit|Microsoft\ Edge\ Helper)\\b", flags="Fi", strict=true)
}, field=[aid], key=[aid], include=[DomainName,ContextBaseFileName,ContextProcessId],mode=inner, max=20000)
| groupBy([ComputerName, aid,#repo], function=([count(aid, as=Connections_Count), min(ContextTimeStamp, as=FirstRquest), max(ContextTimeStamp, as=LastRequest), count(DomainName, as=UniqueDomainCount,distinct=true),collect([ContextBaseFileName,DomainName], limit=20000)]))
| FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
| LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")
```

## Successfull Logon after Bruteforce from same IP with tried user
```logscale
correlate(
  Fail: {
    #event_simpleName=UserLogonFailed2 
    | ContextTimeStamp:=ContextTimeStamp*1000
    | LogonType=10
    | !cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16","127.0.0.0/8","0.0.0.0/32"])
    | !cidr(field=RemoteAddressIP4, file="your_org_asn_prefixes.csv", column="cidr")
  } include:[#repo,aid,ComputerName,UserName,LogonType,RemoteAddressIP4,ContextTimeStamp,Status,SubStatus],

  Success: {
    "#event_simpleName"=UserLogon
    | in(field=LogonType, values=["7","10"])
    | UserName!="vavulnscan"
    | ContextTimeStamp:=ContextTimeStamp*1000
    | !cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16","127.0.0.0/8","0.0.0.0/32"])
    | !cidr(field=RemoteAddressIP4, file="your_org_asn_prefixes.csv", column="cidr")
    
    //| RemoteAddressIP4 <=> Fail.RemoteAddressIP4     // same source IP as the fails
  } include:[#repo,aid,ComputerName,UserName,LogonType,RemoteAddressIP4,ContextTimeStamp],
  sequence=true, within=1h, jitterTolerance=10m,
  root=Success, maxPerRoot=2000,                      // let one success pair with many fails
  globalConstraints=[aid,RemoteAddressIP4]                             // drop UserName if it differs across attempts
)

// keep only fail events that are within 60 seconds BEFORE the success
| DeltaSec := (Success.ContextTimeStamp - Fail.ContextTimeStamp)/1000
| DeltaSec > 0 //and DeltaSec <= 3600
| ComputerName:=Success.ComputerName
| #repo:=Success.#repo
| aid:=Success.aid
| SuspiciousIP4:=Success.RemoteAddressIP4
| SuccessLogonType:=Success.LogonType
| Success_ContextTimeStamp:=Success.ContextTimeStamp
| Success_UserName:=Success.UserName
| Fail_UserNames:=Fail.UserName
| Fail_Status:=Fail.Status
| Fail_SubStatus:=Fail.SubStatus

| groupBy(
    [SuspiciousIP4, #repo,ComputerName,aid, Success_UserName,SuccessLogonType],
    function=([
      count(Fail.ContextTimeStamp, as=FailsLast60m),
      count(Fail.UserName, as=Fail_UserName_counts, distinct=true),
      min(Fail.ContextTimeStamp, as=First_FailContextTimestamp),
      max(Fail.ContextTimeStamp, as=Last_FailContextTimestamp),
      min(Success_ContextTimeStamp, as=First_Success_ContextTimeStamp),
      max(Success_ContextTimeStamp, as=Last_Success_ContextTimeStamp),
      max(DeltaSec, as=max_Fail_Deltasec),
      collect([Fail_UserNames, Fail_Status, Fail_SubStatus], limit=20000)
    ])
  )
| FirstFailTs:=formatTime(format="%F %T.%L", field="FirstFailTs")
| First_Success_ContextTimeStamp:=formatTime(format="%F %T.%L", field="First_Success_ContextTimeStamp")
| Last_Success_ContextTimeStamp:=formatTime(format="%F %T.%L", field="Last_Success_ContextTimeStamp")
| First_FailContextTimestamp:=formatTime(format="%F %T.%L", field="First_FailContextTimestamp")
| Last_FailContextTimestamp:=formatTime(format="%F %T.%L", field="Last_FailContextTimestamp")
// Map Fail_Status
| match(file="ntstatus_status.csv", field=Fail_Status, column="decimal", include="label", strict=false)
| rename(field=label, as=Fail_Status)

// Map Fail_SubStatus
| match(file="ntstatus_substatus.csv", field=Fail_SubStatus, column="decimal", include="label", strict=false)
| rename(field=label, as=Fail_SubStatus)

// threshold: at least 6 failed requests per hor from same IP prior to the success
| FailsLast60m >= 6
| sort(field=[Fail_UserName_counts], order=desc, limit=20000)
```

## Successfull Logon after Bruteforce from same IP with tried user #2
```logscale
correlate(
  Fail: {
    #event_simpleName=UserLogonFailed2
    | ContextTimeStamp:=ContextTimeStamp*1000
    | LogonType=10
    | !cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16","127.0.0.0/8","0.0.0.0/32"])
    | !cidr(field=RemoteAddressIP4, file="your_org_asn_prefixes.csv", column="cidr")
  } include:[#repo,aid,ComputerName,UserName,LogonType,RemoteAddressIP4,ContextTimeStamp,Status,SubStatus],

  Success: {
    "#event_simpleName"=UserLogon
    | in(field=LogonType, values=["7","10"])
    | UserName!="vavulnscan"
    | ContextTimeStamp:=ContextTimeStamp*1000
    | !cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16","127.0.0.0/8","0.0.0.0/32"])
    | !cidr(field=RemoteAddressIP4, file="your_org_asn_prefixes.csv", column="cidr")
    //| RemoteAddressIP4 <=> Fail.RemoteAddressIP4     // same source IP as the fails
  } include:[#repo,aid,ComputerName,UserName,LogonType,RemoteAddressIP4,ContextTimeStamp],

  sequence=true, within=1h, jitterTolerance=10m,
  root=Success, maxPerRoot=2000,                      // let one success pair with many fails
  globalConstraints=[aid,RemoteAddressIP4]                             // drop UserName if it differs across attempts
)

// keep only fail events that are within 60 seconds BEFORE the success
| DeltaSec := (Success.ContextTimeStamp - Fail.ContextTimeStamp)/1000
| DeltaSec > 0 //and DeltaSec <= 3600
| ComputerName:=Success.ComputerName
| #repo:=Success.#repo
| aid:=Success.aid
| SuspiciousIP4:=Success.RemoteAddressIP4
| SuccessLogonType:=Success.LogonType
| Success_ContextTimeStamp:=Success.ContextTimeStamp
| Success_UserName:=Success.UserName
| Fail_UserNames:=Fail.UserName
| Fail_Status:=Fail.Status
| Fail_SubStatus:=Fail.SubStatus

| groupBy(
    [SuspiciousIP4, #repo,ComputerName,aid, Success_UserName,SuccessLogonType],
    function=([
      count(Fail.ContextTimeStamp, as=FailsLast60m),
      count(Fail.UserName, as=Fail_UserName_counts, distinct=true),
      min(Fail.ContextTimeStamp, as=First_FailContextTimestamp),
      max(Fail.ContextTimeStamp, as=Last_FailContextTimestamp),
      min(Success_ContextTimeStamp, as=First_Success_ContextTimeStamp),
      max(Success_ContextTimeStamp, as=Last_Success_ContextTimeStamp),
      max(DeltaSec, as=max_Fail_Deltasec),
      collect([Fail_UserNames, Fail_Status, Fail_SubStatus], limit=20000)
    ])
  )
| FirstFailTs:=formatTime(format="%F %T.%L", field="FirstFailTs")
| First_Success_ContextTimeStamp:=formatTime(format="%F %T.%L", field="First_Success_ContextTimeStamp")
| Last_Success_ContextTimeStamp:=formatTime(format="%F %T.%L", field="Last_Success_ContextTimeStamp")
| First_FailContextTimestamp:=formatTime(format="%F %T.%L", field="First_FailContextTimestamp")
| Last_FailContextTimestamp:=formatTime(format="%F %T.%L", field="Last_FailContextTimestamp")
// Map Fail_Status
| match(file="ntstatus_status.csv", field=Fail_Status, column="decimal", include="label", strict=false)
| rename(field=label, as=Fail_Status)

// Map Fail_SubStatus
| match(file="ntstatus_substatus.csv", field=Fail_SubStatus, column="decimal", include="label", strict=false)
| rename(field=label, as=Fail_SubStatus)

// threshold: at least 6 failed requests per hor from same IP prior to the success
| FailsLast60m >= 6
| sort(field=[Fail_UserName_counts], order=desc, limit=20000)
```

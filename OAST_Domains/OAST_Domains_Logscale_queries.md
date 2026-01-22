# OAST Domains - LogScale Queries

Adjust allowlists and paths to your environment as needed.

## Basic Search for "OAST" DNS requests with Shanon Entropy > 4
```logscale
#event_simpleName="DnsRequest" or #event_simpleName="SuspiciousDnsRequest"
| QueryStatus!="123" // forwarded beyond localhost
| regex("^(?!.*(trellix|aws|google|mcafee|azure|footprint|online-metrix|apple|sharepoint|occloud|forticloud|microsoft)).*$", field=DomainName)
| regex("^(?:[A-Za-z0-9-]+\\.)*(?:interact\\.sh|oast(?:\\.(?:pro|live|site|online|fun|me|today))|oastify\\.com|burpcollaborator\\.net|canarytokens\\.(?:com|org)|dnslog\\.(?:cn|pw|org|store|xyz)|ceye\\.io|eyes\\.sh|tu4\\.org|dig\\.pm|dnsbin\\.zhack\\.ca|hookbin\\.com|smee\\.io|gobygo\\.net)$", field=DomainName)
| not regex("(?i)(firefox|chrome|safari|edge|brave|mcchhost\\.exe|mssense\\.exe|msmpeng\\.exe)", field=ContextBaseFileName)
| Domainb64Entropy := shannonEntropy("DomainName")
| Domainb64Entropy > 4
| groupBy([DomainName,Domainb64Entropy,ComputerName], function=([count(aid, as=Connections_Count), min(ContextTimeStamp, as=FirstRquest), max(ContextTimeStamp, as=LastRequest)]))
| FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
| LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")
```

## Pure OAST DNS requests
```logscale
#event_simpleName="DnsRequest" or #event_simpleName="SuspiciousDnsRequest"
//true OAST callback domains
| QueryStatus!="123" // forwarded beyond localhost
| regex("^(?:[A-Za-z0-9-]+\\.)*(?:interact\\.sh|oast(?:\\.(?:pro|live|site|online|fun|me|today))|oastify\\.com|burpcollaborator\\.net|dnslog\\.(?:cn|pw|org|store|xyz)|ceye\\.io|eyes\\.sh|tu4\\.org|dig\\.pm|dnsbin\\.zhack\\.ca|hookbin\\.com|smee\\.io)$", field=DomainName)
// # public-tunnel / proxy services (handle separately / lower-priority)
    // | regex("^(?:[A-Za-z0-9-]+\\.)*(?:ngrok\\.(?:com|io)|serveo\\.net|pagekite\\.me|localtunnel\\.me|localxpose\\.com|webhook\\.site|teleconsole\\.com|sish\\.net|inlets\\.dev|telebit\\.app|openport\\.io|remote\\.it)$", field=DomainName)

// Exclude lookups coming from user-browser processes or Microsoft Defender mssense,msmpeng or McAfee mcchhost\\.exe
| not regex("(?i)(firefox|chrome|safari|edge|brave|mcchhost\\.exe|mssense\\.exe|msmpeng\\.exe)", field=ContextBaseFileName)


| groupBy([#repo,ComputerName,DomainName,ContextBaseFileName], function=([count(aid, as=Connections_Count), min(ContextTimeStamp, as=FirstRquest), max(ContextTimeStamp, as=LastRequest), collect([@rawstring], limit=20000)]))
| FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
| LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")
```

## Other OAST related/ public-tunnel / proxy services
```logscale
#event_simpleName="DnsRequest" or #event_simpleName="SuspiciousDnsRequest"
| QueryStatus!="123" // forwarded beyond localhost

//true OAST callback domains
//| regex("^(?:[A-Za-z0-9-]+\\.)*(?:interact\\.sh|oast(?:\\.(?:pro|live|site|online|fun|me|today))|oastify\\.com|burpcollaborator\\.net|canarytokens\\.(?:com|org)|dnslog\\.(?:cn|pw|org|store|xyz)|ceye\\.io|eyes\\.sh|tu4\\.org|dig\\.pm|dnsbin\\.zhack\\.ca|hookbin\\.com|smee\\.io|gobygo\\.net)$", field=DomainName)
// # public-tunnel / proxy services (handle separately / lower-priority)
| regex("^(?:[A-Za-z0-9-]+\\.)*(?:ngrok\\.(?:com|io)|serveo\\.net|pagekite\\.me|localtunnel\\.me|localxpose\\.com|webhook\\.site|teleconsole\\.com|sish\\.net|inlets\\.dev|telebit\\.app|openport\\.io|remote\\.it)$", field=DomainName)
// Exclude lookups coming from user-browser processes or Microsoft Defender mssense,msmpeng or McAfee mcchhost\\.exe
| not regex("(?i)(firefox|chrome|safari|edge|brave|mcchhost\\.exe|mssense\\.exe|msmpeng\\.exe|Passwords|PasswordsMenuBarExtra)", field=ContextBaseFileName)
| groupBy([#repo,DomainName,ContextBaseFileName], function=([count(aid, as=Connections_Count), min(ContextTimeStamp, as=FirstRquest), max(ContextTimeStamp, as=LastRequest), collect([@rawstring], limit=20000)]))
| FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
| LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")
```


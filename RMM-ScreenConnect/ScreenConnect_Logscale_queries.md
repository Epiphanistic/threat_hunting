  # ConnectWise ScreenConnect (Control) — Logscale Queries

  ## macOS — LaunchAgent/Daemon persistence via `launchctl`
  Time: 30d
  Purpose: Catch ScreenConnect install/persistence actions via `launchctl` managing LaunchAgents/Daemons.
  ```logscale
  event_platform="Mac" and #event_simpleName=ProcessRollup2
  | CommandLine=/screenconnect/i or CommandLine=/ConnectWise/i
  | regex(field=CommandLine,regex="\blaunchctl\b\s+(?<action>bootstrap|bootout|enable|disable|kickstart|load|
  unload)\b(?:(?!\n).)*?\s(?<plist>/(?:Library|Users/[^/]+/Library)/Launch(?<plist_type>Agents|Daemons)/(?
  <plist_base>[^\s\"']+)\.plist)\b",flags="Fi")
  | "plist_base" != com.crowdstrike.falcon.UserAgent
  | groupBy([ComputerName,aid,plist_base,plist_type], function=([count(aid, as=EventsCount), min(timestamp,
  as=FirstEvent),max(timestamp, as=LastEvent), collect([plist,action,@rawstring], limit=20000)]))
  | FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
  | LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
  | sort(field=LastEvent, order=desc, limit=20000)

  ## macOS — Download provenance (extended attributes) to non-vendor relays

  Time: 1y
  Purpose: Identify ScreenConnect downloads with query params and non-vendor relay hosts.

  event_platform=Mac
  | #event_simpleName=FileExtendedAttrOperation
  | regex(field=ExtendedAttributeValueReadable, flags="i", regex="https?:\\/\\/(?<host_domain>[^\\/\"\\]\\\\\\s]+)\\/(?:
  [Bb]in)\\/[^\\?\"\\]\\\\\\s]+\\?(?<qs>[^\\"\\]\\\\\\s]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)h=(?<relay_host>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)p=(?<relay_port>\\d+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)i=(?<client_id>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)e=(?<mode>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)y=(?<role>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)n=(?<client_name>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)a=(?<auth_mode>[^&;\"'\\]]+)")
  | in(field=mode, values=["Access","Support"])
  | in(field=role, values=["Guest","Host"])
  | relay_host!=/screenconnect\.com/i
  | groupBy([#repo,ComputerName,aid], function=([count(aid, as=EventsCount),
  min(timestamp, as=FirstEvent),max(timestamp, as=LastEvent),
  collect([host_domain,relay_host,relay_port,client_id,mode,role,client_name,auth_mode,@rawstring], limit=20000)]))
  | FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
  | LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
  | sort(field=LastEvent, order=desc, limit=20000)

  ## macOS — Correlate DNS to provenance/attributes (initial access + execution)

  Time: 1y
  Purpose: Link DNS by ScreenConnect binaries to extended-attribute provenance with relay parameters.

  correlate(
    DNS: {
      event_platform=Mac
      | in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
      | (ContextBaseFileName=/ScreenConnect/i or ContextBaseFileName=/ConnectWise/i or ContextBaseFileName=/
  support*client/i)
    } include:[aid,ComputerName,DomainName,ContextBaseFileName,ContextProcessId,@timestamp],

    ATTR: {
      event_platform=Mac
      | #event_simpleName=FileExtendedAttrOperation
      | regex(field=ExtendedAttributeValueReadable, flags="i", regex="https?:\\/\\/(?<host_domain>[^\\/\"\\]\\\\\\s]+)\
  \/(?:[Bb]in)\\/[^\\?\"\\]\\\\\\s]+\\?(?<qs>[^\\"\\]\\\\\\s]+)")
      | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)h=(?<relay_host>[^&;\"'\\]]+)")
      | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)p=(?<relay_port>\\d+)")
      | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)i=(?<client_id>[^&;\"'\\]]+)")
      | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)e=(?<mode>[^&;\"'\\]]+)")
      | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)y=(?<role>[^&;\"'\\]]+)")
      | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)n=(?<client_name>[^&;\"'\\]]+)")
      | regex(field=qs, flags="Fi", strict=false, regex="(?:^|&|;|&amp;|\\u0026)a=(?<auth_mode>[^&;\"'\\]]+)")
      | in(field=mode, values=["Access","Support"])
      | in(field=role, values=["Guest","Host"])
      | relay_host!=/screenconnect\.com/i
    } include:
  [aid,ComputerName,TargetFileName,host_domain,relay_host,relay_port,client_id,mode,role,client_name,auth_mode,@timestam
  p,@rawstring],

    globalConstraints=[aid],
    within=10m
  )
  | dns_time := DNS.@timestamp
  | attr_time := ATTR.@timestamp
  | groupBy([DNS.ComputerName, DNS.aid], function=([
        count(DNS.aid, as=DNS_Counts),
        min(DNS.@timestamp, as=FirstDNS),
        max(DNS.@timestamp, as=LastDNS),
        min(ATTR.@timestamp, as=FirstAttr),
        max(ATTR.@timestamp, as=LastAttr),
        collect([DNS.DomainName, DNS.ContextBaseFileName, DNS.ContextProcessId, ATTR.host_domain, ATTR.relay_host,
  ATTR.relay_port, ATTR.client_id, ATTR.mode, ATTR.role, ATTR.client_name, ATTR.auth_mode], limit=20000)
      ])
  )
  | FirstDNS := formatTime(format="%F %T.%L", field="FirstDNS")
  | LastDNS  := formatTime(format="%F %T.%L", field="LastDNS")
  | FirstAttr:= formatTime(format="%F %T.%L", field="FirstAttr")
  | LastAttr := formatTime(format="%F %T.%L", field="LastAttr")
  | sort(field=LastDNS, order=desc, limit=20000)

  ## macOS — DNS by ScreenConnect binaries

  Time: 1y
  Purpose: Baseline DNS from ScreenConnect/Control processes.

  event_platform=Mac
  | in(field=#event_simpleName, values=["DnsRequest","SuspiciousDnsRequest"])
  | ContextBaseFileName=/ScreenConnect/i or ContextBaseFileName=/ConnectWise/i
  | groupBy([#repo,ComputerName,aid],function=([count(aid, as=EventsCount), min(ContextTimeStamp, as=FirstEvent),
  max(ContextTimeStamp, as=LastEvent), collect([DomainName,ContextProcessId,ContextBaseFileName], limit=20000)]))
  | FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
  | LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
  | sort(field=LastEvent, order=desc)

  ## Windows — HostUrl parameter extraction (IA/execution to non-official hosts)

  Time: 1y
  Purpose: Detect ScreenConnect downloads/execution with HostUrl parameters to non-official relays.

  #event_simpleName=ProcessRollup2 and event_platform="Win"
  | HostUrl!="" and HostUrl=*
  | regex(field=HostUrl, flags="Fi", strict=true,
              regex="https?:\\/\\/(?<host_domain>[^\\/?\"\\]\\\\]+)[^\\s\"\\]]*\\?(?<qs>[^\\"\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|[&;]|&amp;|\\u0026)h=(?<relay_host>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|[&;]|&amp;|\\u0026)p=(?<relay_port>\\d+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|[&;]|&amp;|\\u0026)i=(?<client_id>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|[&;]|&amp;|\\u0026)e=(?<mode>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|[&;]|&amp;|\\u0026)y=(?<role>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|[&;]|&amp;|\\u0026)n=(?<client_name>[^&;\"'\\]]+)")
  | regex(field=qs, flags="Fi", strict=false, regex="(?:^|[&;]|&amp;|\\u0026)a=(?<auth_mode>[^&;\"'\\]]+)")
  | in(field=mode, values=["Access","Support"])
  | in(field=role, values=["Guest","Host"])
  | relay_host!=/screenconnect\.com/i or host_domain!=/screenconnect\.com/i or relay_host!="" or relay_host=*
  | groupBy([#repo,ComputerName,aid],
            function=([count(aid, as=EventsCount),
                       min(timestamp, as=FirstEvent),
                       max(timestamp, as=LastEvent),
                       collect([host_domain,relay_host,relay_port,client_id,mode,role,client_name,auth_mode,@rawstring],
  limit=20000)]))
  | FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
  | LastEvent :=formatTime(format="%F %T.%L", field="LastEvent")
  | sort(field=LastEvent, order=desc, limit=20000)

  ## Windows — Registry/service persistence (ScreenConnect client)

  Time: 1y
  Purpose: Identify ScreenConnect service entries with non-vendor relay parameters.

  event_platform="Win"
  | in(field=#event_simpleName, values=["AsepValueUpdate","AsepKeyUpdate"])
  | regex(field=RegObjectName,regex="\\\\SYSTEM\\\\(?:CurrentControlSet|ControlSet\\d{3})\\\\Services\\\\ScreenConnect
  Client \\((?<service_id>(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]
  {4}-[0-9a-fA-F]{12}))\\)")
  | regex(field=RegStringValue, regex="(?i)(?:\\?|&|\\u0026)h=(?!(?:[^&\\s]*(?:panorama9\\.com)))(?<c2_host>[^&\\s]+)(?
  =(?:&|\\u0026|\\s|$))")
  | regex(field=RegStringValue, regex="(?is).*?\\?(?<mode_preamble>.*?)(?=(?:&|\\u0026|%26)h=).*|(?s).*")
  | regex(field=RegStringValue, regex="(?i)(?:\\?|&|\\u0026|%26)p=(?<c2_port>\\d+)")
  | regex(field=RegStringValue, regex="(?i)(?:\\?|&|\\u0026|%26)s=(?<session_guid>[0-9a-fA-F-]{16,36})")
  | groupBy([#repo,ComputerName,aid,c2_host,c2_port], function=([min(timestamp, as=FirstEvent), max(timestamp,
  as=LastEvent), collect([ContextProcessId,service_guid,mode_preamble,session_guid,@rawstring], limit=20000)]))
  | FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
  | LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
  | sort(field=[LastEvent,#repo], order=desc)

  ## Windows — Registry persistence (broader, excluding screenconnect.com/panorama9)

  Time: 1y
  Purpose: Same as above but without the panorama9 allowance; surfaces any non-vendor relays.

  in(field=#event_simpleName, values=["AsepValueUpdate","AsepKeyUpdate"])
  | regex(field=RegObjectName,regex="\\\\SYSTEM\\\\(?:CurrentControlSet|ControlSet\\d{3})\\\\Services\\\\ScreenConnect
  Client \\((?<service_id>(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]
  {4}-[0-9a-fA-F]{12}))\\)")
  | regex(field=RegStringValue, regex="(?i)(?:\\?|&|\\u0026)h=(?!(?:[^&\\s]*(?:screenconnect\\.com|panorama9\\.com)))(?
  <c2_host>[^&\\s]+)(?=(?:&|\\u0026|\\s|$))")
  | regex(field=RegStringValue, regex="(?is).*?\\?(?<mode_preamble>.*?)(?=(?:&|\\u0026|%26)h=).*|(?s).*")
  | regex(field=RegStringValue, regex="(?i)(?:\\?|&|\\u0026|%26)p=(?<c2_port>\\d+)")
  | regex(field=RegStringValue, regex="(?i)(?:\\?|&|\\u0026|%26)s=(?<session_guid>[0-9a-fA-F-]{16,36})")
  | groupBy([ComputerName,aid,c2_host,c2_port], function=([min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent),
  collect([ContextProcessId,service_guid,mode_preamble,session_guid,@rawstring], limit=20000)]))
  | FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
  | LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
  | sort(field=LastEvent, order=desc)

  ## Windows — DNS by ScreenConnect/ClickOnce (suspicious TLDs)

  Time: 1y
  Purpose: Find ScreenConnect-related binaries doing DNS to risky TLDs.

  in(field=#event_simpleName, values=["SuspiciousDnsRequest","DnsRequest"])
  | in(field=ContextBaseFileName,
  values=["dfsvc.exe","screenconnect.exe","connectwise.exe","screenconnect","connectwise","ScreenConnect","ConnectWise"]
  )
  | regex(
    field=DomainName,
    regex="(?i)^(?:[a-z0-9-]+\\.)+(?:top|xyz|online|live|fun|site|shop|click|space|buzz|help|icu|pw|work|club|link|
  quest|monster|rest|pics|today|guru|email|support|review|stream|download|win|men|bid|loan|date|party|faith|webcam|
  science|gdn|mom|kim|bar|cam|press|pro|best|fit|ooo|info|biz|zip|mov|tk|ml|ga|cf|gq|gg)\\.?$",
    flags=Fi)
  | groupBy([ComputerName,event_platform], function=([count(aid, as=Connections_Count), min(ContextTimeStamp,
  as=FirstRquest), max(ContextTimeStamp, as=LastRequest), collect([DomainName,ContextBaseFileName,@rawstring],
  limit=10000)]))
  | FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
  | LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")

  ## Windows — Installed applications inventory (ScreenConnect/Control)

  Time: 1y
  Purpose: Track installs/uninstalls and version changes.

  #event_simpleName="InstalledApplication"
  | AppName=/screenconnect/i or AppName=/connectwise/i or AppName=/support\.client/i
  | replace(field=UpdateFlag, regex="^0$", with="UPDATE_INVALID")
  | replace(field=UpdateFlag, regex="^1$", with="UPDATE_ENUMERATION")
  | replace(field=UpdateFlag, regex="^2$", with="UPDATE_REMOVED")
  | replace(field=UpdateFlag, regex="^3$", with="UPDATE_ADDED")
  | replace(field=UpdateFlag, regex="^4$", with="UPDATE_OBSOLETE")
  | replace(field=UpdateFlag, regex="^5$", with="UPDATE_REVISED")
  | InstallDate_ms := InstallDate * 1000
  | case {
      UpdateFlag="UPDATE_REMOVED"
    | RemovedTS := timestamp;
      UpdateFlag="UPDATE_ENUMERATION"
    | EnumTS := timestamp;
      * | *
    }
  | groupBy([#repo,ComputerName, aid],
      function=([
        max(RemovedTS, as=MaxRemovedTS),
        max(EnumTS,   as=MaxEnumTS),
        count(aid, as=seen_count),
        min(timestamp, as=FirstSeen),
        max(timestamp, as=LastSeen),
        collect([AppName,AppVersion, AppType, AppVendor, UpdateFlag], limit=20000)
      ])
  )
  | test((MaxRemovedTS <= MaxEnumTS))
  | FirstSeen:=formatTime(format="%F %T.%L", field="FirstSeen")
  | LastSeen:=formatTime(format="%F %T.%L", field="LastSeen")
  | MaxRemovedTS:=formatTime(format="%F %T.%L", field="MaxRemovedTS")
  | MaxEnumTS:=formatTime(format="%F %T.%L", field="MaxEnumTS")
  | sort(#repo, order=asc, limit=20000)
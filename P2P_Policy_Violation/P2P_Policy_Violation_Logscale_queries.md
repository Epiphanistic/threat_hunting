# P2P Policy Violation - LogScale Queries
These queries are untested in your environment and are provided as guidance/examples. Validate and tune before operational use.


Adjust allowlists and
paths to your environment as needed.

## P2P services violating Oracle policy regarding p2p usage
```logscale
#event_simpleName="ProcessRollup2"
// matches Bright SDK and common P2P binaries on Windows (.exe), macOS (.app/Contents/MacOS/…), or as bare Linux/macOS executables
| regex(field=ImageFileName,flags="i",regex="\\b(net_svc|net_updater(?:32|64)|brightsvc|lumprobe|torrent|emule|syncthing|ipfs|go-ipfs|js-ipfs|freenet|i2p|tor|zeronet|oneswarm|slsk|sopcast|acestream|btsync|monerod|litecoind|dogecoind|Shareaza|deluge|retroshare|geth|bitcoind|azureus|transmission-qt|tixati|BitComet|tribler|Popcorn-Time|WebTorrent|FrostWire|LimeWire|amule|DCPlusPlus|Resilio[ -]?Sync|tahoe|gnunet|parity|openethereum|siad|storj|swarm|zerotier-one|hamachi-2|n2n|tox|qtox|jami|hola)(?:\\.exe|\\.app[/\\\\]Contents[/\\\\]MacOS[/\\\\]\\1)?$")
// acestream: Ace Stream P2P multimedia engine for IPTV streaming — risk: covert bidirectional data channels hidden within live video streams
// amule: aMule eDonkey2000 client for segmented P2P file sharing — risk: unsanctioned sync of sensitive files across global peer network
// azureus: Vuze/Azureus Java-based BitTorrent client with plugin ecosystem — risk: exploitable plugins/adware bundling enabling RCE
// BitComet: Hybrid HTTP & BitTorrent client using fallback seeding — risk: HTTP-based exfiltration bypassing P2P filters
// bitcoind: Bitcoin Core node daemon participating in blockchain P2P — risk: persistent encrypted connections can serve as covert C2 tunnels
// brightsvc: Bright SDK Windows service launching P2P telemetry mesh at boot — risk: SYSTEM-level covert channel for data exfiltration
// btsync: Legacy BitTorrent Sync continuous file sync daemon — risk: automated sync of corporate directories without oversight
// DCPlusPlus: Direct Connect hub-based client for segmented downloads — risk: hub-driven file sharing with unvetted peers risking data leaks
// deluge: Deluge BitTorrent client with DHT and PEX support — risk: trackerless swarms facilitating unmonitored malware distribution
// dogecoind: Dogecoin node syncing blockchain over P2P — risk: non-standard ports and long-lived sockets abused for stealth C2
// emule: eMule eDonkey2000 client for large-scale segmented downloads — risk: leeches/uploads may exfiltrate internal data
// freenet: Freenet store-and-forward anonymity network — risk: hidden payload hosting/distribution beyond corporate controls
// FrostWire: Gnutella & BitTorrent client with built-in search — risk: search indexing may deliver malicious torrents or phishing payloads
// geth: Go-Ethereum P2P node syncing blockchain — risk: heavy P2P sync traffic can mask exfiltration and lateral comms
// gnunet: GNUnet privacy P2P framework offering file share & name resolution — risk: encrypted custom protocols bypass IDS/IPS
// hamachi-2: LogMeIn Hamachi mesh VPN creating P2P overlays — risk: bypasses segmentation and firewall policies for lateral movement
// Hola: Hola P2P proxy turning endpoints into exit nodes — risk: unvetted third-party traffic egress and IP spoofing
// i2p: I2P darknet router creating encrypted tunnels — risk: covert C2 and exfiltration via anonymized routing
// ipfs / go-ipfs / js-ipfs: IPFS libp2p daemons for content-addressable storage — risk: persistent hosting of arbitrary data including malware
// jami: Jami P2P chat & VoIP client using DHT — risk: end-to-end encrypted comms bypass corporate monitoring
// litecoind: Litecoin node daemon for blockchain sync — risk: encrypted P2P traffic as covert channel for data exfiltration
// LimeWire: Legacy Gnutella client with known vulnerabilities — risk: unpatched code exploited to drop malware
// lumprobe: Bright SDK probe utility performing P2P connectivity tests — risk: internal network discovery and mapping
// monerod: Monero P2P daemon syncing privacy-focused blockchain — risk: encrypted mesh abused for stealth C2
// net_svc: Bright SDK core P2P service for telemetry exchange — risk: unauthorized data collection/exfiltration channel at SYSTEM level
// net_updater32 / net_updater64: Bright SDK auto-updaters polling P2P mesh — risk: supply-chain attack vector via malicious updates
// oneswarm: OneSwarm friend-to-friend P2P sharing wrapper — risk: trusted peer networks exfiltrating sensitive files
// parity / openethereum: Parity Ethereum P2P client — risk: heavy blockchain sync traffic masking covert comms
// Popcorn-Time: P2P streaming client for video playback — risk: drive-by malware via torrent-based streaming
// Resilio Sync: Commercial BitTorrent-based file synchronizer — risk: stealthy direct sync of proprietary data off-network
// retroshare: RetroShare F2F encrypted P2P network for chat & file exchange — risk: hidden messaging/exfil channels beyond controls
// Shareaza: Multi-network P2P client bridging Gnutella/eDonkey/BitTorrent — risk: aggregated attack surface across protocols
// slsk: Soulseek music-sharing network — risk: malware-laden file swaps and phishing distribution
// sopcast: SopCast P2P IPTV streaming client — risk: high-bandwidth streams used to conceal C2 traffic
// swarm: Ethereum Swarm client for decentralized content distribution — risk: host malicious payloads in a DHT-based CDN
// tahoe: Tahoe-LAFS encrypted storage network daemon — risk: threshold-split exfiltration with plausible deniability
// torrent: Generic BitTorrent client engine joining swarms — risk: wide-scale malware distribution and data exfil via open swarms
// transmission-qt: Transmission GUI client for magnet links — risk: rapid torrent consumption of malicious payloads undetected
// tribler: Tribler anonymity-enhanced torrent client using onion routing — risk: anonymized P2P circuits hiding malicious transfers
// tox / qtox: Tox protocol P2P messaging clients — risk: encrypted C2 and file transfer disguised as chat
// WebTorrent: WebTorrent desktop client streaming over WebRTC — risk: uses browser P2P to evade traditional torrent filters
// zeronet: ZeroNet DHT-based web hosting client — risk: untraceable serving of malicious websites
// zerotier-one: ZeroTier virtual LAN P2P agent — risk: creation of unauthorized LAN tunnels bypassing policies
| groupBy([ComputerName,UserName,#repo], function=([count(aid, as=Events_Count), min(timestamp, as=First_Event), max(timestamp, as=Last_Event), collect([aid,ImageFileName,SHA256HashData,ParentBaseFileName], limit=20000)]))
| First_Event:=formatTime(format="%F %T.%L", field="First_Event")
| Last_Event:=formatTime(format="%F %T.%L", field="Last_Event")
| sort(Last_Event, order=desc, limit=20000)
```

## P2P installs violating Oracle policy regarding p2p usage
```logscale
#event_simpleName="PeFileWritten"
// matches Bright SDK and common P2P binaries on Windows (.exe), macOS (.app/Contents/MacOS/…), or as bare Linux/macOS executables
| regex(field=TargetFileName,flags="i",regex="\\b(net_svc|net_updater(?:32|64)|brightsvc|lumprobe|torrent|emule|syncthing|ipfs|go-ipfs|js-ipfs|freenet|i2p|tor|zeronet|oneswarm|slsk|sopcast|acestream|btsync|monerod|litecoind|dogecoind|Shareaza|deluge|retroshare|geth|bitcoind|azureus|transmission-qt|tixati|BitComet|tribler|Popcorn-Time|WebTorrent|FrostWire|LimeWire|amule|DCPlusPlus|Resilio[ -]?Sync|tahoe|gnunet|parity|openethereum|siad|storj|swarm|zerotier-one|hamachi-2|n2n|tox|qtox|jami|hola)(?:\\.exe|\\.app[/\\\\]Contents[/\\\\]MacOS[/\\\\]\\1)?$")
// acestream: Ace Stream P2P multimedia engine for IPTV streaming — risk: covert bidirectional data channels hidden within live video streams
// amule: aMule eDonkey2000 client for segmented P2P file sharing — risk: unsanctioned sync of sensitive files across global peer network
// azureus: Vuze/Azureus Java-based BitTorrent client with plugin ecosystem — risk: exploitable plugins/adware bundling enabling RCE
// BitComet: Hybrid HTTP & BitTorrent client using fallback seeding — risk: HTTP-based exfiltration bypassing P2P filters
// bitcoind: Bitcoin Core node daemon participating in blockchain P2P — risk: persistent encrypted connections can serve as covert C2 tunnels
// brightsvc: Bright SDK Windows service launching P2P telemetry mesh at boot — risk: SYSTEM-level covert channel for data exfiltration
// btsync: Legacy BitTorrent Sync continuous file sync daemon — risk: automated sync of corporate directories without oversight
// DCPlusPlus: Direct Connect hub-based client for segmented downloads — risk: hub-driven file sharing with unvetted peers risking data leaks
// deluge: Deluge BitTorrent client with DHT and PEX support — risk: trackerless swarms facilitating unmonitored malware distribution
// dogecoind: Dogecoin node syncing blockchain over P2P — risk: non-standard ports and long-lived sockets abused for stealth C2
// emule: eMule eDonkey2000 client for large-scale segmented downloads — risk: leeches/uploads may exfiltrate internal data
// freenet: Freenet store-and-forward anonymity network — risk: hidden payload hosting/distribution beyond corporate controls
// FrostWire: Gnutella & BitTorrent client with built-in search — risk: search indexing may deliver malicious torrents or phishing payloads
// geth: Go-Ethereum P2P node syncing blockchain — risk: heavy P2P sync traffic can mask exfiltration and lateral comms
// gnunet: GNUnet privacy P2P framework offering file share & name resolution — risk: encrypted custom protocols bypass IDS/IPS
// hamachi-2: LogMeIn Hamachi mesh VPN creating P2P overlays — risk: bypasses segmentation and firewall policies for lateral movement
// Hola: Hola P2P proxy turning endpoints into exit nodes — risk: unvetted third-party traffic egress and IP spoofing
// i2p: I2P darknet router creating encrypted tunnels — risk: covert C2 and exfiltration via anonymized routing
// ipfs / go-ipfs / js-ipfs: IPFS libp2p daemons for content-addressable storage — risk: persistent hosting of arbitrary data including malware
// jami: Jami P2P chat & VoIP client using DHT — risk: end-to-end encrypted comms bypass corporate monitoring
// litecoind: Litecoin node daemon for blockchain sync — risk: encrypted P2P traffic as covert channel for data exfiltration
// LimeWire: Legacy Gnutella client with known vulnerabilities — risk: unpatched code exploited to drop malware
// lumprobe: Bright SDK probe utility performing P2P connectivity tests — risk: internal network discovery and mapping
// monerod: Monero P2P daemon syncing privacy-focused blockchain — risk: encrypted mesh abused for stealth C2
// net_svc: Bright SDK core P2P service for telemetry exchange — risk: unauthorized data collection/exfiltration channel at SYSTEM level
// net_updater32 / net_updater64: Bright SDK auto-updaters polling P2P mesh — risk: supply-chain attack vector via malicious updates
// oneswarm: OneSwarm friend-to-friend P2P sharing wrapper — risk: trusted peer networks exfiltrating sensitive files
// parity / openethereum: Parity Ethereum P2P client — risk: heavy blockchain sync traffic masking covert comms
// Popcorn-Time: P2P streaming client for video playback — risk: drive-by malware via torrent-based streaming
// Resilio Sync: Commercial BitTorrent-based file synchronizer — risk: stealthy direct sync of proprietary data off-network
// retroshare: RetroShare F2F encrypted P2P network for chat & file exchange — risk: hidden messaging/exfil channels beyond controls
// Shareaza: Multi-network P2P client bridging Gnutella/eDonkey/BitTorrent — risk: aggregated attack surface across protocols
// slsk: Soulseek music-sharing network — risk: malware-laden file swaps and phishing distribution
// sopcast: SopCast P2P IPTV streaming client — risk: high-bandwidth streams used to conceal C2 traffic
// swarm: Ethereum Swarm client for decentralized content distribution — risk: host malicious payloads in a DHT-based CDN
// tahoe: Tahoe-LAFS encrypted storage network daemon — risk: threshold-split exfiltration with plausible deniability
// torrent: Generic BitTorrent client engine joining swarms — risk: wide-scale malware distribution and data exfil via open swarms
// transmission-qt: Transmission GUI client for magnet links — risk: rapid torrent consumption of malicious payloads undetected
// tribler: Tribler anonymity-enhanced torrent client using onion routing — risk: anonymized P2P circuits hiding malicious transfers
// tox / qtox: Tox protocol P2P messaging clients — risk: encrypted C2 and file transfer disguised as chat
// WebTorrent: WebTorrent desktop client streaming over WebRTC — risk: uses browser P2P to evade traditional torrent filters
// zeronet: ZeroNet DHT-based web hosting client — risk: untraceable serving of malicious websites
// zerotier-one: ZeroTier virtual LAN P2P agent — risk: creation of unauthorized LAN tunnels bypassing policies

| not regex(field=TargetFileName,   flags="i", regex="\\\\Scripts\\\\tox\\.exe$") // whitelisting  Python Tox test‐automation runner in virtualenv
| groupBy([ComputerName,#repo], function=([count(aid, as=Write_Count), min(ContextTimeStamp, as=FirstWrite), max(ContextTimeStamp, as=LastWrite) ,collect([ContextBaseFileName, SHA256HashData,TargetFileName,aid], limit=20000)]))
| FirstWrite:=formatTime(format="%F %T.%L", field="FirstWrite")
| LastWrite:=formatTime(format="%F %T.%L", field="LastWrite")
| sort(LastWrite, order=desc, limit=20000)
```

## hosts connecting to IPFS via non-browser
```logscale
#event_simpleName=DnsRequest
| DomainName=/.*libp2p*./i
| not regex("(?i)(firefox|chrome|safari|edge|brave|mcchhost\\.exe|mssense\\.exe|msmpeng\\.exe|CSFalconService\\.exe|OnVUE\\.exe|TaniumClient|com\\.cisco\\.anyconnect\\.macos\\.acsockext|Arc Helper)", field=ContextBaseFileName)
| groupBy([ComputerName,#repo], function=([count(aid, as=Connections_Count), min(ContextTimeStamp, as=FirstRquest), max(ContextTimeStamp, as=LastRequest), count(DomainName, as=UniqueDomainCount,distinct=true),collect([ContextBaseFileName], limit=20000)]))
| FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
| LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")
| sort(field=LastRequest,order=desc)
```

## Hosts installing Bright SDK directly or bundled
```logscale
| #event_simpleName="PeFileWritten"
| regex(field=TargetFileName,flags="i",regex="(?<BrightExe>(?:net_svc|net_updater(?:32|64)|brightsvc|lumprobe)\.exe)$")
| groupBy([ComputerName,#repo], function=([count(aid, as=Write_Count), min(ContextTimeStamp, as=FirstWrite), max(ContextTimeStamp, as=LastWrite) ,collect([ContextBaseFileName, SHA256HashData,TargetFileName,aid], limit=20000)]))
| FirstWrite:=formatTime(format="%F %T.%L", field="FirstWrite")
| LastWrite:=formatTime(format="%F %T.%L", field="LastWrite")
| sort(LastWrite, order=desc, limit=20000)
```

## Hosts participating in Luminati Network via Bright SDK
```logscale
#event_simpleName="DnsRequest"
| DomainName=/.*\.probe\.tbcache\.com/i
| join({#event_simpleName=WebScriptFileWritten
  | ContextBaseFileName=/net_updater*./i
  }, field=[ContextProcessId], key=[ContextProcessId], include=[TargetFileName, ComputerName, ContextTimeStamp])
| groupBy([ComputerName,#repo], function=([count(aid, as=Connections_Count), min(ContextTimeStamp, as=FirstRquest), max(ContextTimeStamp, as=LastRequest),count(DomainName, as=UniqueDomainsContacted,distinct=true), collect([ContextBaseFileName,TargetFileName], limit=20000)]))
| FirstRquest:=formatTime(format="%F %T.%L", field="FirstRquest")
| LastRequest:=formatTime(format="%F %T.%L", field="LastRequest")
| sort(field=LastRequest,order=desc)
```

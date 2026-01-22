  # ConnectWise ScreenConnect (Control) — External Discovery (Censys)

  ## External discovery — example Censys pivot for suspicious ScreenConnect relays
  Context: A trojanized ScreenConnect client was detected in Oracle Production (hosts impacted since Dec 2024; users
  tricked into downloads). Falcon Complete remediated cases once found; hunt and investigations continue. OverWatch/
  detections point to rogue ScreenConnect servers configured as RATs (no user notification, connect anytime at logon
  via registry keys). Goal: hunt external space for rogue relays to enrich detection/blocking (proxy/EDR) and speed
  response. The steps below are an example workflow and should be tuned to current priorities/IOCs.

  ## Example IOC and fingerprints
  - Seed IP: `51.89.86.115` (from escalation fc-CS-2336715)
  - HTTP body indicators: `RemoteDiagnosticToolkit`, `ScreenConnect`, `ConnectWise Control`, `SC.main.ts`,
  `Script.ashx`, `SC.livedata`
  - JARM: `2ad2ad16d00000022c42d000000000e165b5cbbfb8c1f0c4e1552cac4aa4a9`
  - JA3S: `15af977ce25de452b96affa2addb1036`

  ## Cluster sizing (example)
  Strict search on JA3S+JARM+HTTP bodies in Censys UI returned ~130 hosts:

  services.tls.ja3s: 15af977ce25de452b96affa2addb1036
  and services.jarm.fingerprint: 2ad2ad16d00000022c42d000000000e165b5cbbfb8c1f0c4e1552cac4aa4a9
  and (services.http.response.body:"RemoteDiagnosticToolkit" or services.http.response.body:"ScreenConnect" or
  services.http.response.body:"ConnectWise Control")


  ## Pull full host data (example CLI)
  ```bash
  censys search --index hosts \
    'services.tls.ja3s: 15af977ce25de452b96affa2addb1036 \
     and services.jarm.fingerprint: 2ad2ad16d00000022c42d000000000e165b5cbbfb8c1f0c4e1552cac4aa4a9 \
     and (services.http.response.body:"RemoteDiagnosticToolkit" or services.http.response.body:"ScreenConnect" or
  services.http.response.body:"ConnectWise Control")' \
    --pages -1 --format json \
  | jq -r '.[].ip' | sort -u \
  | while read -r ip; do
      censys view "$ip" > "censys_$ip.json" || echo "view failed for $ip"
      sleep 0.3
    done

  ## Extract domains/metadata for clustering

  # Extract IP and DNS names (example: quick TLD triage)
  jq -r '. | [.ip,.dns.names[]] | @csv' censys_*.json
  # Example hits (TLD “.top” etc.):
  # "104.255.228.103","bayess.top"
  # "216.41.208.205","exch.desktopg.com","mail.desktopg.com","unifi.desktopg.com","remote.desktopg.com"
  # "45.138.16.21","arvrestbnkonline.top"
  # "45.154.98.65","mctel.ascpnlsef.top"

  ## Alternate seeds and cert pivots (examples)

  - Netblock/ASN sweep (example): autonomous_system.asn:16276 AND ip:51.89.86.96/27

    for ip in $(jq -r '.[].ip' asn_16276.json); do
      censys view --index hosts "$ip" > "censys_${ip}_$(date +%F).json"
    done
  - TLS fingerprints (example):
      - services.tls.certificates.leaf_data.fingerprint:"e54d999c52cf367f24ca04887856b642b7ca4a21e612ca3ecf21a56c5bfe6f6
        7"
      - services.tls.certificate.tbs_fingerprint_sha256:"0b336ac03a232d0001ad9e30514257dc330f6d2aa5168f4c31811cd05040c96
        5"
      - services.tls.certificates.leaf_data.names:"logicbridgegroup.com"
  - Combined JA3/JARM/body pivot (alternate JARM):

    censys search --index hosts \
      'services.tls.ja3s: 15af977ce25de452b96affa2addb1036 \
       and services.jarm.fingerprint: 14d14d00014d14d08c000000000000217f0fec773ec97f0b3fdd2de2993c31 \
       and (services.http.response.body:"RemoteDiagnosticToolkit" \
            or services.http.response.body:"ScreenConnect" \
            or services.http.response.body:"ConnectWise Control")'

  ## Post-processing (example summarization)

  jq -r '. as $h
    | ($h.ip // $h.host // $h.name) as $ip
    | ($h.dns?.names // []) as $names
    | $h.services[]?
    | select(.http?.response?.body? // "" | test("ScreenConnect|ConnectWise|Script\\.ashx|SC\\.main\\.ts|
  RemoteDiagnosticToolkit|SC\\.service|SC\\.context"))
    | [ $ip,
        (.port // ""),
        (.http.response.headers?.Server[0]? // .banner // ""),

  (.tls?.certificates?.leaf_data?.fingerprint_sha256 // .tls?.certificates?.leaf_data?.fingerprint // .tls?.certificates
  ?.leaf_fp_sha_256 // ""),
        ($names | join(","))
      ] | @csv' censys_*.json

  ## How to use the external pivots

  - Build/expand a deny list of non-vendor relays and feed into Logscale filters (relay host filters in macOS/Windows
    widgets).
  - Correlate suspicious relays from Censys with endpoint hits (HostUrl, DNS, extended attributes) to confirm exposure.
  - Track reuse of TLS certs/JA3/JARM across infrastructure to spot operator clusters and newly stood-up domains.
  - Feed confirmed bad relays into proxy/firewall blocks and EDR network containment; share with Falcon Complete/CS
    detections for rules.
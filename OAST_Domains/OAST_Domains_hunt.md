# OAST (Out-of-Band Application Security Testing) Domains Hunt

## Executive summary
Out-of-band application security testing (OAST) is a technique used to
detect blind or asynchronous vulnerabilities by forcing a target to make
callbacks to an external system controlled by the tester. Common tooling
includes Burp Collaborator/OASTify and Interactsh, which generate unique
subdomains and record DNS/HTTP interactions as evidence of issues such as
blind SSRF, blind XXE, blind SQLi, blind OS command injection, and similar
conditions where no response is visible to the tester. These same callback
channels can be abused by attackers for covert data exfiltration or for
validating exploitation. This hunt focuses on DNS signals tied to OAST
providers, public tunnel services, and high-entropy subdomains that
resemble OAST payloads.

## Risk if true
- Blind vulnerabilities (SSRF/XXE/RCE) validated via external callbacks.
- Covert DNS or HTTP-based exfiltration using unique subdomain payloads.
- Unauthorized exposure of internal services via public tunneling tools.
- Proxyware or data-collection agents enabling unapproved data paths.
- False positives from legitimate testing or security tooling if not
  explicitly authorized.

## Hypothesis
If OAST activity or related tunneling is present, endpoints will generate
DNS requests to known OAST domains (oastify.com, burpcollaborator.net,
oast.* from Interactsh, and canarytokens.*), with high-entropy subdomains
that encode correlation IDs. Non-browser processes should be the source
of these lookups. Additional signals include callbacks to public tunnel
services (ngrok, localtunnel, webhook.site/dnshook.site) or DNS rebinding
style domains such as plex.direct. DNS answers resolving to RFC1918 ranges
may indicate rebinding or SSRF validation in testing workflows.

## Scope
- In-scope: endpoints and servers with DNS telemetry and process context.
- Time window: 30-90 days for callback activity; 1 year for baselines.
- Out-of-scope: approved red-team or scheduled security testing windows.

## MITRE mapping
- T1190 - Exploit Public-Facing Application: OAST callbacks can validate
  blind SSRF/XXE/RCE on internet-facing services.
- T1071.004 - Application Layer Protocol: DNS: high-entropy DNS queries
  to OAST providers and callback infrastructure.
- T1090.002 - Proxy: External Proxy: public tunnel services used to
  expose internal services or relay C2 traffic.
- T1041 - Exfiltration Over C2 Channel: DNS or HTTP callbacks used for
  exfiltration of small payloads or proof-of-access.

## Data sources
- DNS query/response logs with process context.
- EDR process execution and command-line telemetry.
- Proxy/HTTP logs for HTTP-based callbacks to OAST services.
- Security testing change calendar / approved assessment windows.

## Expected outcome
- Inventory of hosts generating OAST or tunnel-domain DNS queries.
- Separation of approved testing vs. unapproved activity.
- Identification of high-entropy callback domains and suspicious
  non-browser processes.

## LogScale queries
Moved to: [OAST Domains LogScale queries](OAST_Domains_Logscale_queries.md)

## Indicators and context
### OAST providers and callback domains
- Burp Collaborator/OASTify: Burp uses *.burpcollaborator.net and
  *.oastify.com for OAST payloads and callback collection.
- Interactsh: Interactsh is an open-source OAST platform; default public
  servers include oast.pro, oast.live, oast.site, oast.online, oast.fun,
  and oast.me.
- Canarytokens: DNS tokens trigger alerts when their FQDN is resolved and
  can embed small amounts of data in the hostname, which is useful for
  tripwires and beacon-style detections.
- Other DNS loggers: dnslog.*, ceye.io, eyes.sh, tu4.org, dig.pm,
  dnsbin.zhack.ca, hookbin.com, smee.io, gobygo.net (see query regex).

### Public tunnel and webhook services
- ngrok and localtunnel expose local services to the public internet
  for testing and webhook delivery. These can be abused to create
  unauthorized ingress points.
- webhook.site offers DNS/HTTP hooks (dnshook.site) that log all DNS
  requests and can accept encoded data in subdomains, aligning with
  OAST and low-volume exfiltration patterns.

### Benign-but-beacon-like domains
- status.modsecurity.org: ModSecurity's SecStatusEngine sends base32
  encoded telemetry via DNS to status.modsecurity.org when enabled.
- plex.direct: Plex documents DNS rebinding considerations and provides
  guidance for allowing plex.direct on local resolvers, which can result
  in lookups resolving to private IPs and resembling callback patterns.

### Bright SDK / proxyware signals
- Bright SDK (Bright Data) is a data collection component that performs
  web indexing; presence of net_svc/net_updater and *.tbcache.com may
  indicate proxyware-style traffic paths in enterprise environments.

## Triage and response tips
- Validate whether OAST domains align with approved security testing.
- Pivot on non-browser processes generating OAST callbacks.
- Inspect DNS payload entropy and query frequency for exfil patterns.
- Review public tunnel usage (ngrok/localtunnel) for unauthorized
  exposure of internal services.
- Confirm ModSecurity status traffic and plex.direct as expected
  environment-specific behavior before escalation.

## Validation
- Correlate DNS callbacks with process execution and user context.
- Verify whether callbacks are tied to security tooling (Burp or
  Interactsh) or unknown binaries.
- Check for HTTP callbacks following DNS lookups to OAST providers.

## Containment
- Block unapproved OAST or tunnel domains at DNS/proxy layers.
- Remove unauthorized tunnel binaries or proxyware agents.
- Notify testing teams to align scope and avoid false positives.

## Deliverables
- Host list with OAST or tunnel-domain DNS activity.
- Separation of approved testing vs. anomalous callback traffic.
- Recommendations for DNS allowlists/denylists and monitoring.

## Exit criteria
- No unapproved OAST or public-tunnel DNS activity in monitoring window.
- Confirmed benign sources documented or removed.

## References
- https://portswigger.net/blog/oast-out-of-band-application-security-testing
- https://portswigger.net/web-security/ssrf/blind
- https://portswigger.net/burp/documentation/desktop/settings/project/collaborator
- https://docs.projectdiscovery.io/opensource/interactsh/usage
- https://github.com/projectdiscovery/interactsh
- https://docs.canarytokens.org/guide/dns-token
- https://docs.webhook.site/dnshook.html
- https://ngrok.com/docs/agent/overview
- https://localtunnel.app/docs/
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/introducing-modsecurity-status-reporting/
- https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29
- https://support.plex.tv/articles/206225077-how-to-use-secure-server-connections/
- https://help.bright-sdk.com/hc/en-us/articles/20079623475217-What-does-Bright-SDK-do

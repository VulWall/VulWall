---
title: How it works
description: VulWall's architecture and scan pipeline.
---

A VulWall install is four containers:

| Container | What it does |
|-----------|--------------|
| `web` | ASP.NET Core web app: assets, scans, findings, reports and settings. It writes your assets and settings to MongoDB and queues scans. |
| `scanner` | Go program (`nightwatch`) that runs the whole scan pipeline in one process. |
| `mongo` | MongoDB. All application data. |
| `redis` | Redis streams that carry work between the parts of the scanner. |

The web app and the scanner share the MongoDB database and nothing else. There is no HTTP API
between them. To start a scan, the web app inserts a scan with the status `queued`; the scanner
checks for queued scans every 5 seconds, runs the scan and writes the results back.

## The scanner pipeline

The scanner is built from components. Each one does one job, and they talk to each other only
through Redis streams. Only the ingestion components write to MongoDB. This keeps each scanner
simple: it reads a target from a stream and writes findings to another stream.

```text
scan coordinator
  ├─ domains ──▶ domain_discovery_queue ──▶ domain discovery (subfinder)
  │                                           │
  │                                           ▼
  │                                 domain_discovery_results ──▶ domain ingestion ──▶ MongoDB
  │                                                                │
  └─ IPs ──────▶ ip_discovery_queue ◀──────────────────────────────┤ new IPs
                   │                                               │
                   ▼                                               ▼
             port discovery                                domain_scan_triggers
                   │                                               │
                   ▼                                               ├──▶ nuclei
             ip_discovery_results ──▶ port ingestion ──▶ MongoDB   ├──▶ testssl.sh
                                          │                        ├──▶ JavaScript dependencies
                                          ▼                        ├──▶ HTTP headers
                                   port_scan_triggers ──▶ nuclei   └──▶ email security
                                                                           │
                                     security_findings ◀───────────────────┘
                                           │
                                           ▼
                                  findings ingestion ──▶ MongoDB
                                           │
                                           ▼  (new finding types, with an API key)
                                  knowledge-base engine ──▶ knowledge base
```

1. **Scan coordinator.** Starts scans, either on the weekly schedule or when the web app queues
   one. It reads the enabled assets and publishes a discovery job for each domain and IP
   address.
2. **Discovery.** Domain discovery finds subdomains with subfinder and resolves them. Port
   discovery scans a list of common TCP ports on each IP address. It skips IP addresses that
   belong to a CDN.
3. **Ingestion.** Stores what discovery found in the `discoveries` collection, then sends each
   new domain, subdomain and open port to the scanners. It also sends new assets to enrichment,
   which adds WAF, cloud provider and geolocation details.
4. **Scanners.** Each scanner checks the targets it gets and publishes findings. See
   [Scanners](/docs/how-it-works/scanners/).
5. **Findings ingestion.** Stores findings in the `findings` collection. A finding that was seen
   before is updated, not duplicated, and a resolved finding that comes back is opened again.
   For a finding type that VulWall has not seen before, it queues a job for the knowledge-base
   engine, which runs only when `ANTHROPIC_API_KEY` is set.

## When is a scan done?

The scan monitor checks every 5 minutes. A scan is done when every scanner and every ingestion
step has processed all of its work, and no new results have come in for a short time. Two
timeouts are a safety net: a scan with no activity for a while is closed, and no scan runs longer
than 3 hours.

When a scan closes, it marks a finding resolved only when it has proof that the issue is gone.
Missing data never closes a finding:

- **Not reproduced.** The scan found the finding's host again, the scanner that reported the
  finding ran to completion on that host, and it did not report the finding this time. If the
  scanner failed, timed out, or could not reach the host over http or https, the finding stays
  open.
- **Host no longer found.** The host was confirmed gone in 3 scans in a row: for a domain or
  subdomain, your DNS and two public resolvers (1.1.1.1 and 8.8.8.8) all say it has no address;
  for a port, the port scan of its IP finished without finding the port open.

Everything else stays open: findings on a host this scan did not find, on a disabled asset, or
on a host a scan could not fully check. A scan that a timeout closed resolves nothing. Each scan
also re-checks the subdomains earlier scans found, so a live host is not lost when subdomain
enumeration misses it. Set `DNS_RECHECK_RESOLVERS=off` if your network blocks outbound DNS; known
hosts that your resolver cannot find then stay open instead of being confirmed gone.

When discovery could not fully check one of your domains (the domain does not exist, DNS lookups
failed, or subdomain enumeration failed), the web app shows the scan as a "partial scan" with the
number of open issues it could not re-check, and notes the domain on the Assets page. The scan
document records `completion_reason`, `degraded_assets`, `stats.unchecked_findings` and
`unchecked_finding_ids`; a resolved finding records `resolution_reason` (`not_reproduced` or
`host_no_longer_found`) and the scan that resolved it.

Only one scan per organization runs at a time. If the scanner restarts during a scan, it closes
that scan as failed ("Interrupted by restart") at startup. Findings are not marked resolved
because of an incomplete scan.

## Source

The scanner's design documents are in the repository:

- [`scanner/docs/ARCHITECTURE.md`](https://github.com/VulWall/VulWall/blob/main/scanner/docs/ARCHITECTURE.md)
- [`scanner/docs/SERVICE_REGISTRY.md`](https://github.com/VulWall/VulWall/blob/main/scanner/docs/SERVICE_REGISTRY.md):
  every component, stream, consumer group and collection
- [`scanner/docs/DATABASE.md`](https://github.com/VulWall/VulWall/blob/main/scanner/docs/DATABASE.md):
  the MongoDB collections

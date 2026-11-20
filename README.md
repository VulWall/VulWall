# VulWall

VulWall is a self-hosted security scanner for small and medium businesses. You
give it your domains and IP addresses. It finds your external attack surface
(subdomains, IPs, open ports), scans it for vulnerabilities on a schedule, and
shows the results in a web dashboard with plain-language explanations of what
to fix.

<!-- Screenshots: add images to docs/screenshots/ and link them here, e.g.
![Dashboard](docs/screenshots/dashboard.png)
![Findings](docs/screenshots/findings.png)
-->

## Features

- Finds subdomains (with subfinder), resolves them and scans TCP ports on
  your domains and IP addresses.
- Scans for vulnerabilities with:
  - [nuclei](https://github.com/projectdiscovery/nuclei) templates for CVEs,
    exposures, misconfigurations, default logins and takeovers. Intrusive and
    DoS templates are excluded by default.
  - [testssl.sh](https://testssl.sh) for TLS/SSL weaknesses
  - [retire.js](https://retirejs.github.io/retire.js/) for outdated
    JavaScript libraries
  - its own checks for missing or weak HTTP security headers, and for SPF,
    DMARC and DKIM
- Detects WAFs and cloud providers, and looks up the country and network
  owner of each IP with the free DB-IP Lite data.
- The dashboard shows assets, scan history, discoveries, findings and
  reports. Each finding comes with the scanner's own description and,
  when the scanner provides them, remediation advice and references.
- With an Anthropic API key, VulWall also writes business and technical
  remediation guidance for each finding type, and executive summaries. This
  is optional.
- Scans run on a schedule, and you can start one from the UI at any time.
- Everything runs from one `docker compose up` with no external services.
  OpenTelemetry tracing is available but off by default.

## Quick start

You need Docker with Compose v2. We suggest a host with at least 4 GB of RAM.

```bash
git clone https://github.com/VulWall/VulWall.git && cd VulWall
cp .env.example .env        # optional: set ANTHROPIC_API_KEY
docker compose up -d
```

Open http://localhost:8080 and follow the first-run setup. Add a domain you
own, then start a scan.

The first start takes a few minutes: the scanner downloads the nuclei
templates and the geolocation databases. `docker compose logs -f scanner`
shows progress.

## Configuration

All settings are optional and go in `.env`. `.env.example` lists them with
comments.

| Variable | Default | Purpose |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | empty | Enables AI remediation guidance and executive summaries |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Model for the scanner's knowledge-base engine |
| `VULWALL_PORT` | `8080` | Host port of the web UI |
| `VULWALL_VERSION` | `latest` | Image tag of `ghcr.io/vulwall/scanner` and `ghcr.io/vulwall/web` |
| `SECURE_COOKIES` | `false` | Set to `true` when VulWall is served over HTTPS |
| `TRUSTED_PROXIES` | empty | IPs/CIDRs of reverse proxies whose `X-Forwarded-*` headers are trusted |
| `SHARED_LINKS_ENABLED` | `false` | Password-protected shared report links |
| `NUCLEI_WORKERS` | `2` | Concurrent nuclei processes |
| `TESTSSL_CONCURRENCY` | `5` | Concurrent testssl.sh scans |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow scanning private/internal IP ranges |
| `GEO_DOWNLOAD` | `true` | Download DB-IP Lite databases on start |
| `OTEL_ENABLED` | `false` | Export OpenTelemetry traces (see below) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4318` | OTLP/HTTP endpoint |
| `OTEL_EXPORTER_OTLP_HEADERS` | empty | Headers for a hosted OTLP backend |

### HTTPS

VulWall serves plain HTTP on port 8080. To expose it beyond your machine, put
it behind a TLS-terminating reverse proxy (Caddy, Traefik, nginx), set
`SECURE_COOKIES=true` and add the proxy's address to `TRUSTED_PROXIES`.

### Tracing

```bash
echo "OTEL_ENABLED=true" >> .env
docker compose --profile tracing up -d
```

Jaeger runs at http://localhost:16686. Any other OTLP backend works too; see
[scanner/docs/OBSERVABILITY.md](scanner/docs/OBSERVABILITY.md).

## Upgrading

```bash
git pull
docker compose pull          # when you use the published images
docker compose up -d --build # when you build from source
```

Data lives in Docker volumes, so it survives upgrades. Read
[CHANGELOG.md](CHANGELOG.md) before you upgrade, and back up first.

## Backup and restore

All application data is in MongoDB (volume `vulwall_mongo-data`). Redis only
holds work in progress, and the nuclei and geo volumes are downloaded again
when they are missing.

Back up:

```bash
docker compose exec -T mongo mongodump --db vulwall --archive --gzip > vulwall-$(date +%F).archive.gz
```

Restore (this replaces the current data):

```bash
docker compose exec -T mongo mongorestore --drop --archive --gzip < vulwall-2026-01-31.archive.gz
```

## Scan only what you are allowed to scan

VulWall sends active network traffic: port scans, TLS handshakes and
vulnerability probes. Scanning systems without the owner's permission can be
illegal in your country, and it can break your hosting provider's terms of
service. Add only domains and IP addresses that you own or that you have
written permission to test. You alone are responsible for how you use VulWall.
The software comes with no warranty (see the license).

## Repository layout

| Path | What it is |
|------|------------|
| `scanner/` | Go scanning engine (the `nightwatch` binary). See [scanner/README.md](scanner/README.md). |
| `web/` | ASP.NET Core MVC dashboard. |
| `docker-compose.yml` | The self-hosted stack: MongoDB, Redis, scanner, web. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Report security issues privately, as
described in [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 Moji Tajik

VulWall is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License version 3 as published by the
Free Software Foundation. See [LICENSE](LICENSE) for the full text. Third-party
components and data are listed in [NOTICE](NOTICE).

Trademarks: the VulWall name and logo are trademarks of Moji Tajik. The
AGPL covers the code only; it gives no right to use the VulWall name or logo.
If you distribute a modified version, give it a different name.

Source: https://github.com/VulWall/VulWall

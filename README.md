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
- Scans run on the schedule you set in Settings → Scan schedule. Until you
  change it, VulWall scans once a week at a random time at night, and a
  change applies within 5 minutes. You can also start a scan from the UI at
  any time.
- Everything runs from one `docker compose up` with no external services.
  OpenTelemetry tracing is available but off by default.

## Quick start

You need a Linux or macOS host with 4 GB of RAM (recommended) and Docker
with Compose v2. In a test scan of one domain with the default settings, the
stack used up to 1.5 GB, of which the scanner used 1.2 GB. More domains and a
higher `NUCLEI_WORKERS` use more. The CPU must be 64-bit and able to run
MongoDB: AVX on x86-64, ARMv8.2-A on ARM (a Raspberry Pi 5 works, a Pi 4 does
not).

```bash
curl -fsSL https://vulwall.com/install.sh | sh
```

The script checks the host, installs the latest release into `~/vulwall`,
verifies the downloaded files, adds a random first-run setup token to `.env`,
starts the stack and prints the setup link. If port 8080 is taken, it picks a
free port from 8081 to 8099. On Linux without Docker, it offers to install
Docker with Docker's official script; it uses `sudo` only for that, and only
after you say yes. Run it again to upgrade. See the
[documentation](https://vulwall.com/docs) for options.

The script also installs the `vulwall` command for day-to-day tasks:

```bash
~/vulwall/vulwall status       # containers, health and URL
~/vulwall/vulwall backup       # back up the database and .env
~/vulwall/vulwall upgrade      # upgrade to the latest release
~/vulwall/vulwall doctor       # check the host and the scanner's internet access
~/vulwall/vulwall help         # all commands
```

Or install from a clone of this repository:

```bash
git clone https://github.com/VulWall/VulWall.git && cd VulWall
cp .env.example .env        # optional: set ANTHROPIC_API_KEY
echo "SETUP_TOKEN=$(openssl rand -hex 16)" >> .env
docker compose up -d
```

Open `http://localhost:8080/setup?token=<token>` with the token from
`grep SETUP_TOKEN .env` (if you changed `VULWALL_PORT`, use your port). The
token protects setup: without it, `/setup` returns 404. Create the admin
account, add a domain you own, then start a scan.

Without `SETUP_TOKEN`, the web container makes a new random token at each start
and prints the link in its log. Print it with this command, which shows only the
real link line and strips control characters:

```bash
docker compose logs --no-log-prefix web | grep -a '^ *First-run setup: open http://localhost:[0-9]*/setup?token=[0-9a-f]* ' | tail -1 | tr -cd '[:print:]\n'
```

The web UI listens on `127.0.0.1` only. To use it from another machine, see
[Exposing VulWall](#exposing-vulwall).

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
| `VULWALL_PORT` | `8080` | Host port of the web UI (bound to `127.0.0.1`) |
| `SETUP_TOKEN` | empty | First-run setup token. The install script sets a random one; empty means a new random token at each start, printed in the log |
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

### Exposing VulWall

VulWall serves plain HTTP on port 8080, and compose publishes it on
`127.0.0.1` only. To use it from other machines, put it behind a
TLS-terminating reverse proxy (Caddy, Traefik, nginx):

1. Run the proxy on the same host and point it at `http://127.0.0.1:8080`.
   If the proxy runs in Docker, add it to the `vulwall_default` network and
   point it at `http://web:8080` instead.
2. Set `SECURE_COOKIES=true` in `.env`.
3. Add the proxy's address, as VulWall sees it, to `TRUSTED_PROXIES`. For a
   proxy on the host this is the gateway of the `vulwall_default` network
   (`docker network inspect vulwall_default`); for a proxy container, it is
   that container's address on `vulwall_default`.
4. `docker compose up -d`.

Do not publish port 8080 on all interfaces (`"8080:8080"`) to get remote
access. Docker writes its own iptables rules, so ports it publishes bypass
host firewalls such as ufw and firewalld, and anyone who can reach the host
gets plain HTTP.

Login and shared-report passwords are rate-limited per client IP (5 failed
attempts per 15 minutes), and login also has a limit for the admin account (20
attempts per 15 minutes from all IPs). If `TRUSTED_PROXIES` does not match your
proxy, VulWall sees every request as coming from the proxy, so all clients
share one IP limit and a few wrong passwords lock everyone out.

### Tracing

```bash
echo "OTEL_ENABLED=true" >> .env
docker compose --profile tracing up -d
```

Jaeger runs at http://localhost:16686 (bound to `127.0.0.1`; traces include your hostnames and findings, so do not publish it). Any other OTLP backend works too; see
[scanner/docs/OBSERVABILITY.md](scanner/docs/OBSERVABILITY.md).

## Upgrading

With the install script: `~/vulwall/vulwall upgrade`, or run the script again.

From a clone:

```bash
git pull
docker compose pull          # when you use the published images
docker compose up -d --build # when you build from source
```

Data lives in Docker volumes, so it survives upgrades. Read
[CHANGELOG.md](CHANGELOG.md) before you upgrade, and back up first.

Release images carry a signed build provenance attestation. To check that an
image was built from this repository by its release workflow:

```bash
gh attestation verify oci://ghcr.io/vulwall/web:0.1.0 --owner VulWall
```

See [Verify a release](https://vulwall.com/docs/operations/upgrade/#verify-a-release).

## Backup and restore

All application data is in MongoDB (volume `vulwall_mongo-data`). Redis only
holds work in progress, and the nuclei and geo volumes are downloaded again
when they are missing. The `vulwall_web-keys` volume holds the keys that sign
login cookies; if you lose it, you only have to log in again.

With the install script, `~/vulwall/vulwall backup` and
`~/vulwall/vulwall restore <file>` do the steps below.

Back up:

```bash
docker compose exec -T mongo mongodump --db vulwall --archive --gzip > vulwall-$(date +%F).archive.gz
```

Restore (this replaces the current data):

```bash
docker compose exec -T mongo mongorestore --drop --archive --gzip < vulwall-2026-01-31.archive.gz
```

## Lost admin password

VulWall has one admin account. To replace it, delete it and run the
first-run setup again. Your assets, scans and findings stay. With the install
script, `~/vulwall/vulwall reset-admin` does this and prints a new setup link.
Otherwise:

```bash
docker compose stop web
docker compose exec mongo mongosh vulwall --quiet --eval 'db.users.deleteOne({_id:"admin"})'
docker compose start web
grep SETUP_TOKEN .env
```

Open `http://localhost:8080/setup?token=<token>` with that token (use your
`VULWALL_PORT` if you changed it) and create the admin account again. If `.env`
has no `SETUP_TOKEN`, print the new link from the log instead:

```bash
docker compose logs --no-log-prefix web | grep -a '^ *First-run setup: open http://localhost:[0-9]*/setup?token=[0-9a-f]* ' | tail -1 | tr -cd '[:print:]\n'
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

## Roadmap

Planned work, each tracked in a GitHub issue:

- [Notifications](https://github.com/VulWall/VulWall/issues/1)
- [OpenAI-compatible and local AI models](https://github.com/VulWall/VulWall/issues/2)
- [Export and a read-only API](https://github.com/VulWall/VulWall/issues/3)
- [Multiple users with roles](https://github.com/VulWall/VulWall/issues/4)
- [Scan profiles](https://github.com/VulWall/VulWall/issues/5)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Report security issues privately, as
described in [SECURITY.md](SECURITY.md).

## License

VulWall is released under the [MIT License](LICENSE).
Copyright (c) 2026 Moji Tajik.

Third-party tools and data bundled in the container images keep their own
licenses; see [NOTICE](NOTICE).

Trademarks: the VulWall name and logo are trademarks of Moji Tajik. The MIT
License covers the code only; it gives no right to use the VulWall name or
logo. If you distribute a modified version, give it a different name.

Source: https://github.com/VulWall/VulWall

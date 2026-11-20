---
title: Configuration
description: Every setting in VulWall's .env file, with its default.
---

All settings are optional and go in the `.env` file next to `docker-compose.yml` (`~/vulwall/.env`
if you used the install script). `.env.example` lists them with comments. After you change
`.env`, apply it with:

```sh
docker compose up -d
```

Docker Compose recreates the containers whose settings changed. Your data is kept.

## Web app

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULWALL_PORT` | `8080` | Host port of the web UI. It is bound to `127.0.0.1` only. |
| `SECURE_COOKIES` | `false` | Set to `true` when you serve VulWall over HTTPS. Turns on Secure cookies, HSTS and the HTTP to HTTPS redirect. See [Reverse proxy and HTTPS](/docs/configuration/reverse-proxy/). |
| `TRUSTED_PROXIES` | empty | Comma-separated IP addresses or CIDR ranges of reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Proto` headers are trusted. Empty means loopback only. |
| `SHARED_LINKS_ENABLED` | `false` | `true` turns on password-protected shared report links. When `false`, the share option is hidden and shared links return 404. |
| `SETUP_TOKEN` | empty | Fixed first-run setup token for unattended installs. Empty means a random token, printed in `docker compose logs web` at each start. |

## Scanner

| Variable | Default | Purpose |
|----------|---------|---------|
| `NUCLEI_WORKERS` | `2` | Number of nuclei processes that run at the same time. Each one can use several hundred MB of RAM. |
| `TESTSSL_CONCURRENCY` | `5` | Number of testssl.sh scans that run at the same time. |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow scans of private and internal IP ranges. Turn it on only to scan your internal network. |
| `GEO_DOWNLOAD` | `true` | Download the free DB-IP Lite geolocation databases at start. Set to `false` on hosts without internet access. |

## AI (optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | empty | Turns on AI remediation guidance and executive summaries. See [AI recommendations](/docs/configuration/ai/). |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Model for the scanner's knowledge-base engine. |

## Tracing (optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `OTEL_ENABLED` | `false` | Export OpenTelemetry traces from the scanner. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4318` | OTLP/HTTP endpoint. The default is the bundled Jaeger. |
| `OTEL_EXPORTER_OTLP_HEADERS` | empty | Extra headers for a hosted OTLP backend, for example `authorization=Bearer <token>`. |
| `OTEL_SERVICE_NAME` | `vulwall-scanner` | `service.name` reported in traces. |
| `JAEGER_UI_PORT` | `16686` | Host port of the Jaeger UI (`tracing` profile only), bound to `127.0.0.1`. |

See [Logs and tracing](/docs/operations/logs-and-tracing/).

## Images

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULWALL_VERSION` | `latest` | Image tag of `ghcr.io/vulwall/scanner` and `ghcr.io/vulwall/web`. Used only by the compose file in the git repository; the compose file from the install script pins the release. |

## Private targets

By default the scanner does not scan private, loopback, link-local (including cloud metadata
addresses) or other reserved IP ranges. This keeps a target's DNS records from pointing the
scanner at your own network. Set `ALLOW_PRIVATE_TARGETS=true` only when you mean to scan internal
systems.

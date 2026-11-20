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
| `SETUP_TOKEN` | empty | First-run setup token: only someone with it can create the admin account. The install script adds a random one to `.env`; for a manual install, generate one with `openssl rand -hex 16`. Empty means a new random token at each start, printed in `docker compose logs web`. |

## Scanner

| Variable | Default | Purpose |
|----------|---------|---------|
| `NUCLEI_WORKERS` | `2` | Number of nuclei processes that run at the same time. Each one can use several hundred MB of RAM. |
| `NUCLEI_RATE_LIMIT` | `30` | Requests per second that each nuclei process sends. If nuclei sends faster than your connection can handle, connections time out and nuclei stops scanning that site, so the scan misses its findings and the scanner log says the target was "unresponsive". Lower the value if you see that. Raise it on a fast connection to finish scans sooner. |
| `NUCLEI_INTERACTSH` | `off` | Set to `on` to run nuclei's out-of-band (OAST) checks, which find blind issues such as SSRF. A vulnerable target then calls back to an interactsh server: ProjectDiscovery's public servers (`oast.pro`, `oast.live` and others) unless you run your own. Those servers see the callbacks, so they learn which of your sites is vulnerable. While this is off, nuclei skips the templates that need it. |
| `NUCLEI_INTERACTSH_SERVER` | empty | The https URL of your own interactsh server. A value that is not an https URL keeps the checks off; the scanner log says why. |
| `NUCLEI_INTERACTSH_TOKEN` | empty | Auth token of your interactsh server. It is never written to the log. |
| `NUCLEI_TEMPLATE_UPDATE_CRON` | `0 2 * * *` | When nuclei updates its templates, as a 5-field cron expression (minute, hour, day of month, month, day of week) in UTC. The default is every day at 02:00. The scanner also updates the templates once at start. An invalid expression stops the scheduled updates; the scanner log says why. |
| `NUCLEI_INCLUDE_TAGS` | `cve,vuln,exposure,misconfig,default-login,token,takeover,kev,xss,lfi,ssrf,rce,sqli,auth-bypass,unauth,panel` | Comma-separated nuclei template tags to run. Empty means the default. |
| `NUCLEI_EXCLUDE_TAGS` | `intrusive,dos,fuzz` | Comma-separated nuclei template tags to skip. Empty means the default. **Warning:** these exclusions keep scans safe for production sites. If you remove `intrusive`, `dos` or `fuzz`, nuclei sends attack payloads, fuzzing and floods that can change data on, or take down, the sites you scan. |
| `TESTSSL_CONCURRENCY` | `5` | Number of testssl.sh scans that run at the same time. |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow scans of private and internal IP ranges. Turn it on only to scan your internal network. |
| `GEO_DOWNLOAD` | `true` | Download the free DB-IP Lite geolocation databases at start. Set to `false` on hosts without internet access. |
| `GEO_MAX_AGE_DAYS` | `35` | Age in days after which the geolocation databases are downloaded again at start. |
| `CLOUD_DETECTOR_ENABLED` | `true` | Label IP addresses that belong to AWS, Azure, GCP or Fastly. At start the scanner downloads those providers' published IP range lists. Set to `false` on hosts without internet access. |
| `DNS_RESOLVE_CONCURRENCY` | `50` | Number of DNS lookups that run at the same time when domain discovery resolves subdomains. |
| `DNS_RECHECK_RESOLVERS` | `1.1.1.1,8.8.8.8` | Public DNS resolvers the scanner asks directly when your local resolver says a name does not exist: a root domain, a subdomain an earlier scan found, or a domain's SPF, DMARC, MX or NS record. Set your own comma-separated resolvers, or `off` to stop all of these lookups. With `off` the local answer is final: a missing email record is reported as missing, and a subdomain is never confirmed gone. |

## AI (optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | empty | Turns on AI remediation guidance and executive summaries. See [AI recommendations](/docs/configuration/ai/). |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Model for AI remediation guidance (scanner) and executive summaries (web app). |

## Tracing (optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `OTEL_ENABLED` | `false` | Export OpenTelemetry traces from the scanner. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4318` | OTLP/HTTP endpoint. The default is the bundled Jaeger. |
| `OTEL_EXPORTER_OTLP_HEADERS` | empty | Extra headers for a hosted OTLP backend, for example `authorization=Bearer <token>`. |
| `OTEL_SERVICE_NAME` | `vulwall-scanner` | `service.name` reported in traces. |
| `OTEL_TRACES_SAMPLER` | `parentbased_always_on` | Which traces to keep: `always_on`, `always_off`, `parentbased_always_on`, `probabilistic` or `parentbased_probabilistic`. Any other value means the default. |
| `OTEL_TRACES_SAMPLER_ARG` | `0.1` | Fraction of traces (0 to 1) that the probabilistic samplers keep. |
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

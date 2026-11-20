# VulWall Web

The web app for a self-hosted VulWall install: add domains and IP addresses, start scans, and read
findings, recommendations and reports. Built with ASP.NET Core MVC (.NET 10) on MongoDB.

The scanner (`../scanner`) does the scanning. The two share one MongoDB database and nothing else:
the web app queues scans by writing to the `scans` collection, and the scanner writes the results
back.

## Features

- **Assets**: add domains and IP addresses. They are enabled and scanned right away. Only scan
  assets you own or are authorized to test.
- **Scans**: scan history, live status and an on-demand "Scan now".
- **Discoveries**: subdomains, IPs, open ports and services found by the scanner.
- **Recommendations**: fix guidance per finding. With an Anthropic API key the scanner builds an
  AI knowledge base; without one you get the scanner's own description and reference links.
- **Reports**: summary and technical reports. With an Anthropic API key the summary report gets
  an AI executive summary. Password-protected shared links are optional (`SHARED_LINKS_ENABLED`).
- **Settings**: organization name, industry, website and logo.

## Quick start

From the repository root, `docker compose up` starts MongoDB, the scanner and this app. Open
<http://localhost:8080>. On the first visit you are sent to `/setup`, where you create the admin
account (email and a password of at least 10 characters) and name your organization. After that,
`/setup` is closed and you sign in at `/login`.

## Run locally

Requires the .NET 10 SDK and a MongoDB you can reach.

```bash
cd src
MONGO_URI=mongodb://localhost:27017 MONGO_DB=vulwall dotnet run
```

`src/Properties/launchSettings.example.json` is a starting point for IDE run profiles. Copy it to
`launchSettings.json` (git-ignored) to use it.

Tests start a throwaway MongoDB through EphemeralMongo, which downloads a `mongod` binary on the
first run:

```bash
dotnet test
```

## Docker

```bash
docker build -t vulwall-web .        # run from web/
docker run -p 8080:8080 -e MONGO_URI=mongodb://host.docker.internal:27017 vulwall-web
```

The image runs as the non-root `app` user, listens on port 8080 and has a healthcheck on `/health`.

## Configuration

All settings are environment variables. None of them is a secret except `ANTHROPIC_API_KEY`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB` | `vulwall` | Database name (shared with the scanner) |
| `PORT` | `8080` | HTTP port |
| `ANTHROPIC_API_KEY` | empty | Optional. Enables AI executive summaries on reports |
| `DEFAULT_AI_MODEL` | `claude-sonnet-4-6` | Anthropic model for executive summaries |
| `SECURE_COOKIES` | `false` | Set to `true` when the app is served over HTTPS. Turns on Secure cookies, HSTS and the HTTP to HTTPS redirect. Leave `false` for plain `http://localhost` |
| `TRUSTED_PROXIES` | empty | Comma-separated IPs or CIDR ranges of reverse proxies whose `X-Forwarded-For`/`X-Forwarded-Proto` headers are trusted (for example `10.0.0.0/8`). Empty: only loopback is trusted |
| `SHARED_LINKS_ENABLED` | `false` | `true` enables password-protected shared report links. When `false` the share UI is hidden and `/shared-reports/*` returns 404 |
| `VULWALL_VERSION` | `dev` | Version shown in the About dialog. Set at image build time with the `VULWALL_VERSION` build argument; release images use the tag, and the root `make build` passes `dev (<short commit>)` |

Behind a TLS-terminating reverse proxy, set `SECURE_COOKIES=true` and add the proxy to
`TRUSTED_PROXIES` so the app sees the original scheme and client IP (login rate limiting is per IP).

## How it works

- **Sign-in**: one local admin, stored in the `users` collection with a BCrypt password hash.
  Login is rate-limited per IP. Data-protection keys (cookie encryption) are stored on disk in
  `DATA_PROTECTION_KEYS_DIR` (`/data/keys`, a web-only volume in the image), so sessions survive
  restarts. They are not in the shared MongoDB database.
- **Organization**: a self-hosted install has one organization. The app creates it at startup with
  a random weekly scan schedule (`scan_settings.scan_cron`, UTC), which the scanner reads. Settings →
  Scan schedule changes it (Off, daily, weekly or monthly, at a time in a chosen time zone); the
  scanner picks up a change within 5 minutes.
- **Scans**: "Scan now" and adding an asset insert a `scans` document with `status: "queued"`. The
  scanner picks it up. A scan counts as in progress while it is `queued`, `pending` or `running`
  (for at most 24 hours).
- **Executive summaries**: a background job checks every 30 seconds for finished scans and writes
  one AI summary per scan when `ANTHROPIC_API_KEY` is set. Without a key the report shows the
  standard overview instead.
- **Flags and provider logos**: put PNG files in `src/wwwroot/images/logos/countries/{code}.png`
  (ISO 3166-1 alpha-2, lowercase) and `src/wwwroot/images/logos/cloud/{provider}.png` (for
  example `aws.png`, `cloudflare.png`). Without them the discoveries list shows a generic icon.

## Project structure

```
web/
├── Dockerfile
├── VulWall.sln
├── docs/COMPONENTS.md           # UI component system and CSS variables
├── src/                         # Application (dotnet run from here)
│   ├── Program.cs
│   ├── Common/                  # Shared services, views, utilities
│   ├── Data/                    # MongoDB entities and repositories
│   ├── Extensions/              # DI setup, pipeline, MongoDB configuration
│   └── Verticals/               # Account, Assets, Dashboard, Discoveries,
│                                # Recommendations, Reports, Scans, Settings
└── tests/VulWall.Dashboard.Tests/
```

## Documentation

- [CLAUDE.md](CLAUDE.md): development conventions and architecture rules
- [docs/COMPONENTS.md](docs/COMPONENTS.md): UI component system and CSS variables

Report bugs and ask questions at <https://github.com/VulWall/VulWall/issues>.

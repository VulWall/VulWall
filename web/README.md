# VulWall Dashboard

Web application for security assessment management, vulnerability monitoring, and reporting. Built with ASP.NET Core MVC.

## Features

- **Asset Management** — Add domains/IPs, verify ownership, track asset status
- **Scan Management** — View scan history, results, and findings overview
- **Discovery Browser** — Explore discovered subdomains, ports, and services
- **AI Recommendations** — AI-powered security recommendations for findings
- **Reports** — Summary and Technical reports, with optional password-protected shared links (`SHARED_LINKS_ENABLED`)
- **Settings** — Account management, preferences

## Tech Stack

- **Backend**: .NET 10.0, C#, ASP.NET Core MVC
- **Frontend**: Razor Views, Bootstrap 5, FontAwesome
- **Database**: MongoDB
- **Auth**: Auth0 (multi-tenant, org-scoped)
- **AI**: Anthropic Claude (security recommendations)

## Project Structure

```
VulWall.Dashboard/
├── CLAUDE.md
├── README.md
├── VulWall.sln
├── docs/                        # Setup guides and references
│   ├── AUTH0_SETUP.md
│   └── COMPONENTS.md
├── ops/                         # Docker build
│   └── dockerfile
└── src/                         # Application source
    ├── VulWall.Dashboard.csproj
    ├── Program.cs
    ├── Common/                  # Shared logic, views, services
    ├── Data/                    # MongoDB entities and repositories
    ├── Extensions/              # DI setup, configuration
    ├── Middleware/               # Request pipeline middleware
    └── Verticals/               # Vertical slice architecture
        ├── Assets/
        ├── Dashboard/
        ├── Discoveries/
        ├── Recommendations/
        ├── Reports/
        ├── Scans/
        ├── Settings/
        └── Webhooks/
```

## Quick Start

### Prerequisites

- .NET 10.0 SDK
- MongoDB (Atlas or local)
- Auth0 account (see [docs/AUTH0_SETUP.md](docs/AUTH0_SETUP.md))

### Run Locally

```bash
dotnet run --project src/VulWall.Dashboard.csproj
```

### Docker

```bash
docker build -f ops/dockerfile -t vulwall-dashboard .
docker run -p 5000:8080 vulwall-dashboard
```

## Configuration

Environment variables:

| Variable | Purpose |
|----------|---------|
| `AUTH0_DOMAIN` | Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret |
| `MONGO_URI` | MongoDB connection string (include DB name in path, e.g. `mongodb+srv://host/VulWall-Dev`) |
| `SHARED_LINKS_ENABLED` | `true` enables password-protected shared report links. Default `false`: the share UI is hidden and `/shared-reports/*` returns 404 |
| `TRUSTED_PROXIES` | Comma-separated IPs or CIDR ranges of reverse proxies whose `X-Forwarded-For`/`X-Forwarded-Proto` headers are trusted (e.g. `10.0.0.0/8`). Empty: only loopback is trusted |

## Documentation

- **[CLAUDE.md](CLAUDE.md)** — Development conventions, architecture rules, component patterns
- **[docs/AUTH0_SETUP.md](docs/AUTH0_SETUP.md)** — Auth0 multi-tenant configuration
- **[docs/COMPONENTS.md](docs/COMPONENTS.md)** — UI component system and CSS variables

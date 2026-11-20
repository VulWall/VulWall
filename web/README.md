# VulWall Dashboard

Web application for security assessment management, vulnerability monitoring, and reporting. Built with ASP.NET Core MVC.

## Features

- **Asset Management** — Add domains/IPs, verify ownership, track asset status
- **Scan Management** — View scan history, results, and findings overview
- **Discovery Browser** — Explore discovered subdomains, ports, and services
- **AI Recommendations** — AI-powered security recommendations for findings
- **Reports** — Summary and Technical reports with shared link support
- **Security Certificate** — Public-facing security certificate with embeddable badge
- **Settings** — Account management, subscription billing (Stripe), preferences

## Tech Stack

- **Backend**: .NET 10.0, C#, ASP.NET Core MVC
- **Frontend**: Razor Views, Bootstrap 5, FontAwesome
- **Database**: MongoDB
- **Auth**: Auth0 (multi-tenant, org-scoped)
- **Payments**: Stripe (subscriptions)
- **AI**: Anthropic Claude (security recommendations)

## Project Structure

```
VulWall.Dashboard/
├── CLAUDE.md
├── README.md
├── VulWall.sln
├── docs/                        # Setup guides and references
│   ├── AUTH0_SETUP.md
│   ├── COMPONENTS.md
│   └── STRIPE_SETUP.md
├── ops/                         # Docker and Railway config
│   ├── dockerfile
│   └── railway.toml
└── src/                         # Application source
    ├── VulWall.Dashboard.csproj
    ├── Program.cs
    ├── Common/                  # Shared logic, views, services
    ├── Data/                    # MongoDB entities and repositories
    ├── Extensions/              # DI setup, configuration
    ├── Middleware/               # Request pipeline middleware
    └── Verticals/               # Vertical slice architecture
        ├── Assets/
        ├── Claim/
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
- Stripe account (see [docs/STRIPE_SETUP.md](docs/STRIPE_SETUP.md))

### Run Locally

```bash
dotnet run --project src/VulWall.Dashboard.csproj
```

### Docker (Railway)

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
| `STRIPE_SECRET_KEY` | Stripe secret key |
| `STRIPE_PUBLISHABLE_KEY` | Stripe publishable key |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `STRIPE_BASE_PLAN_PRICE_ID` | Stripe price ID for base plan |

## Documentation

- **[CLAUDE.md](CLAUDE.md)** — Development conventions, architecture rules, component patterns
- **[docs/AUTH0_SETUP.md](docs/AUTH0_SETUP.md)** — Auth0 multi-tenant configuration
- **[docs/STRIPE_SETUP.md](docs/STRIPE_SETUP.md)** — Stripe subscription integration
- **[docs/COMPONENTS.md](docs/COMPONENTS.md)** — UI component system and CSS variables

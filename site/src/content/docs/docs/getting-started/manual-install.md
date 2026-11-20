---
title: Install from the repository
description: Install VulWall with git clone and Docker Compose.
---

Use this method if you want to build the images from source, follow `main`, or see every step.

```sh
git clone https://github.com/VulWall/VulWall.git && cd VulWall
cp .env.example .env        # optional: set ANTHROPIC_API_KEY
docker compose up -d
```

`docker compose up -d` pulls the published images `ghcr.io/vulwall/scanner` and
`ghcr.io/vulwall/web` with the tag in `VULWALL_VERSION` (default `latest`). To pin a release, set
`VULWALL_VERSION=0.1.0` in `.env`.

To build the images from your checkout instead:

```sh
docker compose up -d --build
```

The first start takes a few minutes: the scanner downloads the nuclei templates and the
geolocation databases. `docker compose logs -f scanner` shows progress.

## Get the setup link

The web app prints a one-time setup link to its log when no admin account exists:

```sh
docker compose logs web | grep "First-run setup" | tail -1
```

The link looks like `http://localhost:8080/setup?token=...`. It always shows the container port
8080. If you changed `VULWALL_PORT`, use your port instead.

Each start of the web container prints a new token, and only the latest one works. Without a
valid token, `/setup` returns 404, so only someone who can read the server logs can create the
admin account. For unattended installs, set a fixed token with `SETUP_TOKEN` in `.env`.

Open the link and continue with [your first scan](/docs/getting-started/first-scan/).

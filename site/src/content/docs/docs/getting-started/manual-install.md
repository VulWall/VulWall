---
title: Install from the repository
description: Install VulWall with git clone and Docker Compose.
---

Use this method if you want to build the images from source, follow `main`, or see every step.

```sh
git clone https://github.com/VulWall/VulWall.git && cd VulWall
cp .env.example .env        # optional: set AI_API_KEY
echo "SETUP_TOKEN=$(openssl rand -hex 16)" >> .env
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

## Open the setup page

Only someone with the setup token can create the admin account: without a valid token, `/setup`
returns 404. Get the token you put in `.env`:

```sh
grep SETUP_TOKEN .env
```

and open `http://localhost:8080/setup?token=<token>`. If you changed `VULWALL_PORT`, use your
port instead of 8080.

If you leave `SETUP_TOKEN` empty, the web container makes a new random token at each start, and
only the latest one works. It prints the setup link to its log when no admin account exists.
This command prints only the real link line and strips control characters:

```sh
docker compose logs --no-log-prefix web | grep -a '^ *First-run setup: open http://localhost:[0-9]*/setup?token=[0-9a-f]* ' | tail -1 | tr -cd '[:print:]\n'
```

The link always shows the container port 8080.

Open the link and continue with [your first scan](/docs/getting-started/first-scan/).

---
title: Install with the script
description: Install VulWall with one command.
---

```sh
curl -fsSL https://vulwall.com/install.sh | sh
```

The script installs VulWall into `~/vulwall` and starts it. It does not use `sudo`, and it does
not change anything outside that directory except Docker's own images, containers and volumes.
You can [read it](/install.sh) before you run it; the source is
[`install.sh`](https://github.com/VulWall/VulWall/blob/main/install.sh) in the repository.

## What the script does

1. Checks that `docker` and `docker compose` (v2) are installed and that the Docker daemon is
   reachable.
2. Downloads `docker-compose.yml`, `env.example` and `SHA256SUMS` from the latest
   [GitHub release](https://github.com/VulWall/VulWall/releases), and checks the two files against
   `SHA256SUMS`. If the check fails, it stops and changes nothing.
3. Writes `docker-compose.yml` and `.env.example` into the install directory. It creates `.env`
   from `.env.example` only if `.env` does not exist yet, so your settings are never overwritten.
4. Runs `docker compose pull` and `docker compose up -d`.
5. Waits until the web app reports healthy, then prints the link to the first-run setup page. If
   the admin account already exists, it prints the login URL instead.

When it is done you see something like this:

```text
VulWall is running. Open this link to create the admin account:

  http://localhost:8080/setup?token=4f0c...
```

Open the link and continue with [your first scan](/docs/getting-started/first-scan/).

## Options

Set these environment variables for the `sh` that runs the script:

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULWALL_DIR` | `$HOME/vulwall` | Install directory |
| `VULWALL_VERSION` | latest release | Release to install, for example `0.1.0` |

```sh
curl -fsSL https://vulwall.com/install.sh | VULWALL_DIR=$HOME/apps/vulwall VULWALL_VERSION=0.1.0 sh
```

The compose file of a release pins the scanner and web images to that release. The
`VULWALL_VERSION` setting in `.env` has no effect on it; it is only used by the compose file in
the git repository. To change version, run the script again with `VULWALL_VERSION`.

## Files in the install directory

| File | What it is |
|------|------------|
| `docker-compose.yml` | The stack. The script replaces it on every run, so do not edit it. |
| `.env` | Your settings. See [Configuration](/docs/configuration/). |
| `.env.example` | The default settings of the installed release, with comments. |
| `docker-compose.override.yml` | Optional. Docker Compose reads it automatically; put your own changes to the stack here. |

Run `docker compose` commands from this directory, for example `cd ~/vulwall && docker compose ps`.

## Upgrade and uninstall

To upgrade, run the script again. See [Upgrade](/docs/operations/upgrade/).

To stop VulWall and keep your data:

```sh
cd ~/vulwall && docker compose down
```

To remove VulWall and **delete all its data**:

```sh
cd ~/vulwall && docker compose down -v && cd && rm -rf ~/vulwall
```

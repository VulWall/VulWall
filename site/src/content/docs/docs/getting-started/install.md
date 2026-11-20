---
title: Install with the script
description: Install VulWall with one command.
---

```sh
curl -fsSL https://vulwall.com/install.sh | sh
```

The script installs VulWall into `~/vulwall` and starts it. It uses `sudo` only to install or
start Docker, and only after you say yes. Apart from that, it changes nothing outside the install
directory except Docker's own images, containers and volumes, and an optional link to the
`vulwall` command in `~/.local/bin`. You can [read it](/install.sh) before you run it; the source
is [`install.sh`](https://github.com/VulWall/VulWall/blob/main/install.sh) in the repository.

## What the script does

1. Checks the host before it changes anything: Linux or macOS (on Windows, use WSL 2), a 64-bit
   CPU that MongoDB supports (see [Requirements](/docs/getting-started/requirements/#cpu)), and
   `curl`. If a check fails, it explains why and stops.
2. Checks that `docker` and `docker compose` (v2) are installed and that the Docker daemon is
   running. On Linux, it can install or start Docker for you; see
   [If Docker is missing](#if-docker-is-missing).
3. Warns if Docker has less than 2 GB of memory, or if the disk has less than 5 GB free.
4. Downloads `docker-compose.yml`, `env.example`, `vulwall` and `SHA256SUMS` from the latest
   [GitHub release](https://github.com/VulWall/VulWall/releases), and checks the files against
   `SHA256SUMS`. If the check fails, it stops and changes nothing.
5. Writes the files into the install directory. It creates `.env` from `.env.example` only if
   `.env` does not exist yet, so your settings are never overwritten. If `.env` has no
   `SETUP_TOKEN`, it adds a random one (32 hex characters). It never changes a `SETUP_TOKEN` you
   set.
6. Picks the web UI port. See [Port](#port).
7. Runs `docker compose pull` and `docker compose up -d`.
8. Waits until the web app and the scanner report healthy. If a container keeps crashing, it
   stops at once and shows that container's last log lines. If the scanner is not healthy after
   4 minutes, it warns you and continues. The usual cause is missing outbound internet access.
9. Prints the link to the first-run setup page, made from the `SETUP_TOKEN` in `.env`. If the
   admin account already exists, it prints the login URL instead.

When it is done you see something like this:

```text
VulWall is running. Open this link to create the admin account:

  http://localhost:8080/setup?token=4f0c...
```

Open the link and continue with [your first scan](/docs/getting-started/first-scan/). The link
works until you create the admin account. To see the token again, run
`grep SETUP_TOKEN ~/vulwall/.env`.

### Over SSH

The web UI listens on `127.0.0.1` of the server only. If you run the script over SSH, it also
prints an SSH command that forwards the port to your own computer, for example:

```sh
ssh -L 8080:localhost:8080 alice@203.0.113.10
```

Run it on your own computer and keep it open, then open the setup link in your browser. To reach
VulWall without a tunnel, set up a [reverse proxy with HTTPS](/docs/configuration/reverse-proxy/).

## If Docker is missing

On Linux, if Docker is not installed, the script asks:

```text
Docker is not installed. Install Docker Engine now using Docker's official script (needs sudo)? [y/N]
```

If you answer `y`, it downloads Docker's install script from `https://get.docker.com`, runs it
with `sudo`, starts Docker, and adds your user to the `docker` group. The group change takes
effect at your next login, so for the rest of the install the script runs `docker` with `sudo`.
Log out and back in to use `docker` and the `vulwall` command without `sudo`.

If Docker is installed but not running, the script offers to start it with
`sudo systemctl start docker`. If the Compose plugin is missing and Docker's package repository is
set up, it offers to install the `docker-compose-plugin` package.

The script asks on your terminal, also when you run it with `curl ... | sh`. Without a terminal,
for example in automation, it does nothing with `sudo` unless you set `VULWALL_INSTALL_DOCKER=1`.

On macOS, install [Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/)
(or run `brew install --cask docker`), start it, and run the script again.

## Port

The web UI uses port 8080 on `127.0.0.1`. If another program already uses that port, the script
picks the first free port from 8081 to 8099, saves it as `VULWALL_PORT` in `.env`, and tells you.
It does this only if you have not set `VULWALL_PORT`. If you set `VULWALL_PORT` and that port is in
use by another program, the script stops with an error. If you set it for the script, as in
`VULWALL_PORT=8090 sh`, and `.env` has no `VULWALL_PORT` yet, the script saves it in `.env`.

## Options

Set these environment variables for the `sh` that runs the script:

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULWALL_DIR` | `$HOME/vulwall` | Install directory |
| `VULWALL_VERSION` | latest release | Release to install, for example `0.1.0` |
| `VULWALL_PORT` | `8080`, or the first free port from 8081 | Port of the web UI on `127.0.0.1` |
| `VULWALL_INSTALL_DOCKER` | not set | `1` installs or starts Docker on Linux without asking |
| `VULWALL_SKIP_CPU_CHECK` | not set | `1` skips the CPU check |

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
| `vulwall` | The [`vulwall` command](#the-vulwall-command). |
| `docker-compose.override.yml` | Optional. Docker Compose reads it automatically; put your own changes to the stack here. |
| `.docker-compose.release.yml` | A copy of `docker-compose.yml` as the script installed it. |
| `docker-compose.yml.bak.<time>` | Your edited `docker-compose.yml`, if you changed it. |

If you edit `docker-compose.yml`, the next run of the script saves your version as
`docker-compose.yml.bak.<time>` before it replaces the file, and tells you. Move your changes to
`docker-compose.override.yml`.

Run `docker compose` commands from this directory, for example `cd ~/vulwall && docker compose ps`.

## The vulwall command

The script installs `~/vulwall/vulwall`, a small shell script for common tasks. If
`~/.local/bin` is on your `PATH`, the script offers to link it there, so you can type `vulwall`
from any directory.

| Command | What it does |
|---------|--------------|
| `vulwall status` | Shows the containers and their health, the installed release, the images and the URL |
| `vulwall logs [service]` | Follows the logs of all services, or of `web`, `scanner`, `mongo` or `redis` |
| `vulwall upgrade` | Runs the install script again for this directory. See [Upgrade](/docs/operations/upgrade/). |
| `vulwall backup [file]` | Backs up the database and `.env`. See [Back up and restore](/docs/operations/backup/). |
| `vulwall restore <file>` | Replaces all data with a backup |
| `vulwall reset-admin` | Deletes the admin account and prints a new setup link. See [Reset the admin password](/docs/operations/admin-password/). |
| `vulwall doctor` | Checks Docker, the CPU, memory, disk space, the containers, and whether the scanner can reach GitHub and DB-IP |
| `vulwall uninstall` | Stops VulWall and deletes the install directory with all data |
| `vulwall version` | Shows the installed release and images |

`restore`, `reset-admin` and `uninstall` ask before they change anything. Add `-y` to skip the
question, for example in a script: `vulwall -y reset-admin`.

## Upgrade and uninstall

To upgrade, run `vulwall upgrade` or the script again. See [Upgrade](/docs/operations/upgrade/).

To stop VulWall and keep your data:

```sh
cd ~/vulwall && docker compose down
```

To remove VulWall and **delete all its data**, run `vulwall uninstall`, or:

```sh
cd ~/vulwall && docker compose down -v && cd && rm -rf ~/vulwall
```

## Verify the download

The script checks the downloaded files against `SHA256SUMS`, and the compose file of a release
pins each image by digest. To check that the images were built by VulWall's release workflow,
see [Verify a release](/docs/operations/upgrade/#verify-a-release).

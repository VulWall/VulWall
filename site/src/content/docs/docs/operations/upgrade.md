---
title: Upgrade
description: Upgrade VulWall to a new release.
---

Read the [changelog](/changelog/) before you upgrade, and [make a backup](/docs/operations/backup/).
Your data is kept in Docker volumes, so it survives upgrades.

## Installed with the script

Run the install script again:

```sh
curl -fsSL https://vulwall.com/install.sh | sh
```

It downloads the compose file of the latest release, keeps your `.env`, pulls the new images and
restarts the containers that changed. Use the same `VULWALL_DIR` as for the install if you
changed it.

To install a specific release, or to go back to an older one:

```sh
curl -fsSL https://vulwall.com/install.sh | VULWALL_VERSION=0.1.0 sh
```

New releases can add settings. Compare your `.env` with the new `.env.example` to see them.

## Installed with git clone

```sh
git pull
docker compose pull          # when you use the published images
docker compose up -d --build # when you build from source
```

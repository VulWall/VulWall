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

## Verify a release

The install script checks the files it downloads against the release's `SHA256SUMS`. The compose
file of a release pins each image by tag and digest, for example
`ghcr.io/vulwall/web:0.1.0@sha256:...`, so the image cannot change after the release.

Each release image also has a signed build provenance attestation. It shows that the image was
built from the VulWall repository by its release workflow. Check it with the
[GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify oci://ghcr.io/vulwall/web:0.1.0 --owner VulWall
gh attestation verify oci://ghcr.io/vulwall/scanner:0.1.0 --owner VulWall
```

Replace `0.1.0` with your release. To check the exact images your install runs, use the
`image:` values from `docker-compose.yml` in the install directory.

## Installed with git clone

```sh
git pull
docker compose pull          # when you use the published images
docker compose up -d --build # when you build from source
```

---
title: Upgrade
description: Upgrade VulWall to a new release.
---

Read the [changelog](/changelog/) before you upgrade, and [make a backup](/docs/operations/backup/).
Your data is kept in Docker volumes, so it survives upgrades.

## Installed with the script

```sh
~/vulwall/vulwall upgrade
```

This downloads the install script from `https://vulwall.com/install.sh` and runs it for the
install directory. Running the script yourself does the same:

```sh
curl -fsSL https://vulwall.com/install.sh | sh
```

It downloads the compose file of the latest release, keeps your `.env`, pulls the new images and
restarts the containers that changed. Use the same `VULWALL_DIR` as for the install if you
changed it. If you edited `docker-compose.yml`, it saves your version as
`docker-compose.yml.bak.<time>` first; put your changes in `docker-compose.override.yml`
instead.

To install a specific release, or to go back to an older one:

```sh
VULWALL_VERSION=0.1.0 ~/vulwall/vulwall upgrade
```

New releases can add settings. Compare your `.env` with the new `.env.example` to see them.

## Upgrade from 0.2 or earlier

VulWall 0.2 and earlier ran MongoDB 7. Later releases run MongoDB 9, which cannot open a MongoDB 7
database: the `mongo` container stops with exit code 62 and "UPGRADE PROBLEM" in its log. The
upgrade does not change your data. To keep it, move it with a backup:

```sh
cd ~/vulwall
VULWALL_VERSION=0.2.0 ./vulwall upgrade   # back to MongoDB 7
./vulwall backup                          # note the file name it prints
docker compose down -v                    # deletes the VulWall volumes
./vulwall upgrade                         # MongoDB 9, empty database
./vulwall restore <backup file>
```

Without `restore`, you start again with an empty database and create the admin account again.

Going back from a later release to 0.2 needs the same steps the other way: MongoDB 7 cannot open
a MongoDB 9 database either. Run `./vulwall backup` on the later release, then
`docker compose down -v`, `VULWALL_VERSION=0.2.0 ./vulwall upgrade` and `./vulwall restore`.

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
docker compose pull && docker compose up -d   # when you use the published images
docker compose up -d --build                  # when you build from source
```

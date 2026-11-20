---
title: Requirements
description: What a host needs to run VulWall.
---

## Software

- **Docker** with the **Compose v2** plugin (`docker compose`, not `docker-compose`). Docker
  Engine on Linux and Docker Desktop on macOS and Windows both work.
- For the [install script](/docs/getting-started/install/): a POSIX shell, `curl`, and
  `sha256sum` or `shasum`. Your user must be able to run `docker` without `sudo`.

The images are published for `linux/amd64` and `linux/arm64`.

## Memory

Plan for **4 GB of RAM**. In a test scan of one domain with the default settings, the whole stack
used up to 1.5 GB, of which the scanner used 1.2 GB. More domains and a higher `NUCLEI_WORKERS`
use more memory: each nuclei process can use several hundred MB.

## Network

The scanner needs outbound internet access. Besides the traffic to your targets, it downloads the
nuclei templates, the DB-IP Lite geolocation databases and the published IP ranges of some cloud
providers. The first start takes a few minutes because of these downloads.

On a host without internet access, set `GEO_DOWNLOAD=false`. Scans of internet targets need
internet access in any case.

The web UI needs no inbound port open to the internet. It listens on `127.0.0.1` only. See
[Reverse proxy and HTTPS](/docs/configuration/reverse-proxy/) to reach it from other machines.

## Permission to scan

Add only domains and IP addresses that you own or that you have written permission to test.
Some hosting providers also require you to tell them before you scan. Check your provider's
terms.

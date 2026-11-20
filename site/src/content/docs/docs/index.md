---
title: VulWall documentation
description: Install, configure and run VulWall, the self-hosted external attack surface scanner.
---

VulWall is a self-hosted security scanner for small and medium businesses. You give it your
domains and IP addresses. It finds your external attack surface (subdomains, IP addresses and
open ports), scans it for vulnerabilities on a schedule, and shows the results in a web dashboard
with advice on what to fix.

Everything runs on your own machine with Docker Compose: MongoDB, Redis, the scanner and the web
app. VulWall needs no account and no external service.

## Start here

- [Requirements](/docs/getting-started/requirements/): what the host needs.
- [Install with the script](/docs/getting-started/install/): one command.
- [Install from the repository](/docs/getting-started/manual-install/): `git clone` and
  `docker compose up`.
- [Your first scan](/docs/getting-started/first-scan/): create the admin account and scan a
  domain.

## Run it

- [Configuration](/docs/configuration/): every setting in `.env`.
- [Reverse proxy and HTTPS](/docs/configuration/reverse-proxy/): reach VulWall from other
  machines.
- [Upgrade](/docs/operations/upgrade/), [back up and restore](/docs/operations/backup/),
  [reset the admin password](/docs/operations/admin-password/) and
  [read logs and traces](/docs/operations/logs-and-tracing/).

## Understand it

- [How it works](/docs/how-it-works/): the scan pipeline.
- [Scanners](/docs/how-it-works/scanners/): what each scanner checks.
- [FAQ](/docs/faq/)

:::caution[Scan only what you are allowed to scan]
VulWall sends active network traffic: port scans, TLS handshakes and vulnerability probes.
Scanning systems without the owner's permission can be illegal, and it can break your hosting
provider's terms of service. Add only domains and IP addresses that you own or that you have
written permission to test.
:::

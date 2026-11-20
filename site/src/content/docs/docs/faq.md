---
title: FAQ
description: Common questions about VulWall.
---

## Using VulWall

### What do I need to run it?

A machine with Docker and Compose v2, 4 GB of RAM and internet access, and the domains or IP
addresses you want to scan. It does not need agents on your servers, code changes or credentials
for your systems. See [Requirements](/docs/getting-started/requirements/).

### Do I need security knowledge to use it?

You need to be comfortable running Docker on a server. You do not need to be a security expert to
read the results: each finding comes with a description, advice on how to fix it and references,
and with an [Anthropic API key](/docs/configuration/ai/) also guidance written for business and
technical readers.

### What does it check?

Subdomains, open ports, known vulnerabilities and misconfigurations (nuclei), TLS (testssl.sh),
outdated JavaScript libraries (retire.js), HTTP security headers, and email security (SPF, DMARC,
DKIM). See [Scanners](/docs/how-it-works/scanners/).

### How long does a scan take?

It depends on how much VulWall finds. A domain with a few subdomains and open ports is quicker
than one with hundreds of subdomains. The Scans page shows the progress, and
`docker compose logs -f scanner` shows the details.

### How many domains can I add?

As many as your server can handle. More assets mean longer scans and more memory use; see
`NUCLEI_WORKERS` and `TESTSSL_CONCURRENCY` in [Configuration](/docs/configuration/).

### Can several people use it?

A VulWall install has one organization and one admin account. To share a report, open it and
click **Print / Save as PDF** above the report, then choose "Save as PDF" in your browser's print
dialog.

### Can it scan my internal network?

Not by default. The scanner skips private and internal IP ranges. Set
`ALLOW_PRIVATE_TARGETS=true` to allow them.

### Does it run on ARM?

Yes. The images are published for `linux/amd64` and `linux/arm64`. On ARM, the CPU must implement
ARMv8.2-A for MongoDB: a Raspberry Pi 5 works, a Raspberry Pi 4 does not. See
[Requirements](/docs/getting-started/requirements/#cpu).

### Can I install without Docker?

No. VulWall needs MongoDB, Redis, .NET, Node.js and several scanners, each at a tested version.
Docker keeps all of that to one command and away from the rest of your server. On Linux, the
[install script](/docs/getting-started/install/#if-docker-is-missing) can install Docker for you.

## Your data

### Where are my scan results stored?

In the MongoDB database on your own server, in the Docker volume `vulwall_mongo-data`. You decide
how it is backed up and when it is deleted. See [Back up and restore](/docs/operations/backup/).

### What leaves my server?

- **Scan traffic** to the domains and IP addresses you add.
- **Subdomain discovery:** subfinder looks up your domain names in public passive sources, such as
  certificate transparency logs.
- **Downloads:** nuclei templates (from GitHub), the DB-IP Lite geolocation databases and the
  published IP ranges of AWS, Azure, Google Cloud and Fastly.
- **DNS rechecks:** if your local resolver says a name does not exist, the scanner asks 1.1.1.1
  and 8.8.8.8 directly. It does this for root domains, for subdomains an earlier scan found, and
  for the SPF, DMARC, MX and NS records of your domains. Set `DNS_RECHECK_RESOLVERS=off` to stop all
  of these lookups, or set your own resolvers. See [Configuration](/docs/configuration/#scanner).
- **Out-of-band checks, only if you set `NUCLEI_INTERACTSH=on`:** nuclei then makes a vulnerable
  target call back to an interactsh server. Unless you run your own (`NUCLEI_INTERACTSH_SERVER`),
  that is one of ProjectDiscovery's public servers (`oast.*`), which then sees the callbacks and
  so learns which of your sites is vulnerable. See [Configuration](/docs/configuration/#scanner).
- **AI, only if you set `ANTHROPIC_API_KEY`:** finding details go to Anthropic's API. See
  [what is sent](/docs/configuration/ai/#what-is-sent-to-anthropic).
- **Traces, only if you turn on tracing:** to the OTLP backend you configure.
- **Update check, only when you click Check for updates** in the About dialog: the web app asks
  the GitHub API (`api.github.com`) for the latest VulWall release. It never checks on its own.

VulWall sends no telemetry or usage data to the project.

## Safety

### Will scanning slow down or break my website?

VulWall sends real traffic: port scans, TLS handshakes and many HTTP requests from nuclei. It
does not run nuclei templates tagged `intrusive`, `dos` or `fuzz`, and it limits how many
scans run at the same time. Scan a fragile or very
small system with care, and tell your hosting provider first if its terms ask you to.

### Is it legal to scan with VulWall?

Scanning your own systems, or systems you have written permission to test, is normal security
practice. Scanning other people's systems without permission can be illegal. See
[Security](/docs/security/#scan-only-what-you-are-allowed-to-scan).

### What if I think a finding is wrong?

Scanners can be wrong, and not every finding matters in every situation. Each finding shows the
scanner that reported it, its description and references, so you can judge it. When a later scan
no longer detects a finding, VulWall marks it as resolved.

## Compliance and other tools

### Is VulWall enough for SOC 2 or ISO 27001?

No. VulWall can cover the technical vulnerability scanning of your public-facing systems, and its
reports can serve as evidence. It is not a certification, and it does not replace audits,
policies or internal controls.

### Does VulWall help with NIS2?

For the technical part. It helps you check your public-facing systems regularly and keep a
record of findings over time. NIS2 also covers governance, policies, incident handling and supply
chains, which VulWall does not.

### How is VulWall different from Snyk?

They look at different things. Snyk and similar tools scan your source code, dependencies and
containers, usually in your CI pipeline. VulWall scans what can be reached from the internet
after you deploy: hosts, open ports, TLS, headers and email settings. Many teams use both kinds of
tool.

### Can VulWall replace a penetration test?

No. A penetration test finds problems that automated scanners cannot, such as flaws in business
logic. A pentest is a snapshot, though, and VulWall checks your external attack surface every week
between tests. Use pentests for depth and VulWall in between.

### Can it replace a security person?

No. It does the routine work of watching your external attack surface and explains what it finds.
It does not replace security leadership, secure architecture or internal security work.

## Project

### Is VulWall free?

Yes. VulWall is free and open-source software under the MIT License. See
[License and trademark](/docs/license/).

### Where do I report a bug or ask a question?

Open an issue on [GitHub](https://github.com/VulWall/VulWall/issues). Report security
vulnerabilities privately, as described in [Security](/docs/security/).

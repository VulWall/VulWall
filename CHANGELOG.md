# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First open-source, self-hosted release, under the MIT License.

### Added

#### Install and operations

- `docker compose up -d` runs the whole stack: MongoDB, Redis, the scanner
  and the web app. Settings live in `.env`; `ANTHROPIC_API_KEY` is the only
  one you are likely to want.
- An install script that checks the host before it changes anything. It
  stops on Windows shells (use WSL 2), on 32-bit systems and on CPUs that
  MongoDB cannot run on (no AVX on x86-64; older than ARMv8.2-A on ARM, such
  as the Raspberry Pi 4); `VULWALL_SKIP_CPU_CHECK=1` skips the CPU check. It
  warns when Docker has less than 2 GB of memory or the disk less than 5 GB
  free.
- On Linux the install script offers to install Docker with Docker's
  official script, to start a stopped Docker daemon and to install a missing
  Compose plugin. It asks first and uses `sudo` only for these steps;
  `VULWALL_INSTALL_DOCKER=1` agrees without asking.
- The install script picks a free port from 8081 to 8099 when 8080 is taken
  and saves it as `VULWALL_PORT`. It stops with the last log lines when a
  container keeps crashing (with CPU advice when MongoDB stops on an illegal
  instruction), waits for the scanner to become healthy, prints the `ssh -L`
  command when you install over SSH, and keeps a locally edited
  `docker-compose.yml` as `docker-compose.yml.bak.<time>`.
- The `vulwall` command: `status`, `logs`, `upgrade`, `backup`, `restore`,
  `reset-admin`, `doctor`, `uninstall` and `version`. The install script
  puts it in the install directory and can link it into `~/.local/bin`. Like
  the other release files, it is checked against `SHA256SUMS`.
- `make build` and `make up` in the repository root build the images from
  source. Those images show `dev (<short commit>)` as their version;
  `VULWALL_BUILD_VERSION` sets the text for a plain `docker compose build`.
- Optional OpenTelemetry tracing to any OTLP backend, with a Jaeger profile
  in the compose file.
- CI (build, vet, tests including the MongoDB- and Redis-backed scanner
  tests, actionlint), multi-arch release images (amd64, arm64) and
  Dependabot.
- Sample data for demos and screenshots: `make demo` or `scripts/demo-seed`
  loads the fictional "Acme Demo" (`.test` domains, documentation IP ranges,
  six weekly scans, real scanner texts); `--reset` removes it again.

#### Scanning

- One scanner binary (`nightwatch`) in one image (`ghcr.io/vulwall/scanner`)
  with pinned, checksum-verified nuclei, testssl.sh and retire.js, running
  as a non-root user.
- The web app and the scanner share no HTTP API: the web app queues a scan
  in MongoDB (`scans.status = "queued"`) and the scanner picks it up.
- Adding an asset or pressing Scan now while a scan runs queues one
  follow-up scan, which starts when the scanner is free and includes every
  asset added until it starts. Only one scan waits per organization.
- Scheduled scans: off, daily, weekly or monthly at a time of your choice.
  The schedule uses your browser's time zone and is stored as a UTC cron in
  `scan_settings`; a daylight-saving change moves the local time by one
  hour. If the server does not know the browser's time zone, it does not
  save the schedule and says why.
  The Settings page, the sidebar and the Scans page show the next scan, and
  the scanner picks up a changed schedule within 5 minutes.
- nuclei scans domains and subdomains by hostname, so TLS SNI and the Host
  header reach sites behind a CDN, WAF or virtual host. Every address of the
  name must be public before the run. Open ports are scanned by IP and port,
  except on a CDN edge address (Cloudflare, Fastly, CloudFront, Azure Front
  Door): its ports 80 and 443 are left to the scan by name, and another open
  port is scanned as `<name>:<port>` when it answers. nuclei by IP waited
  minutes on each such port and then dropped it. Findings of a
  `<name>:<port>` run are not resolved by later scans: resolve them by hand,
  or they close when the port stays closed for 3 scans. A CDN edge address
  added as an IP asset gets no nuclei scan (its port scan still runs); the
  Discoveries page marks such an address as a CDN edge.
- `NUCLEI_RATE_LIMIT` (default 30) sets the requests per second of each
  nuclei process. At nuclei's own 150, a home or office connection times out
  and nuclei drops the target.
- nuclei's out-of-band (OAST) checks are off by default. With
  `NUCLEI_INTERACTSH=on`, a vulnerable target calls back to ProjectDiscovery's
  public interactsh servers, or to your own with `NUCLEI_INTERACTSH_SERVER`
  and `NUCLEI_INTERACTSH_TOKEN`.
- `.env` also sets which nuclei template tags run (`NUCLEI_INCLUDE_TAGS`,
  `NUCLEI_EXCLUDE_TAGS`; the default skips `intrusive`, `dos` and `fuzz`) and
  when the templates update (`NUCLEI_TEMPLATE_UPDATE_CRON`, daily at 02:00
  UTC). `CLOUD_DETECTOR_ENABLED=false` stops the download of cloud provider
  IP ranges, and `ANTHROPIC_MODEL` picks the model for both the remediation
  guidance and the executive summaries.
- A finding is resolved only on evidence: as `not_reproduced` when its host
  was found again and the scanner that reported it finished on that host
  without reporting it, or as `host_no_longer_found` when the host was
  confirmed gone in 3 scans in a row. Every scanner records per-host coverage
  (the `scan_coverage` collection, kept 90 days). A check that did not
  finish (a dropped target, a block or WAF challenge, a tool error) is
  coverage `error`: it resolves nothing, but the findings it did report are
  still recorded (except nuclei matches from a run whose target blocked the
  scanner, which may come from the block page).
- A scan that could not check everything is shown as a "partial scan" with
  the affected assets; its findings stay open and the next scan that checks
  the asset settles them. A scan cut off by a scanner restart is closed as
  "Interrupted by restart" and resolves nothing.
- A scan stays open while a scanner still works on a target, also when one
  nuclei run takes longer than the 30 minutes after which the scan monitor
  treats queued work as stuck.
- Domain discovery re-checks the subdomains earlier scans found and retries
  only failed DNS lookups, not names that do not exist. Before the scanner
  treats a domain, a known subdomain or an email record as missing, it asks
  public resolvers (`DNS_RECHECK_RESOLVERS`, default `1.1.1.1,8.8.8.8`,
  `off` to disable).
- Findings keep the scanners' own `remediation` and `references`, so they
  are useful without the AI knowledge base. The knowledge base and the AI
  executive summary are optional and run only with `ANTHROPIC_API_KEY`; a
  failed summary is retried twice, and scans from the last 7 days get one
  once the key is set.
- A stream message that keeps failing is retried 3 times, then moved to
  the `dead_letter` stream. A message that makes a component panic is logged
  and skipped instead of crashing the scanner.
- IP geolocation from the free DB-IP Lite country and ASN databases,
  downloaded at start (`GEO_DOWNLOAD=false` turns that off), with the
  attribution the license asks for on the Discoveries page.

#### Web app

- Country flags and logos for the major clouds and hosting providers ship
  with the app (flag-icons, simple-icons), so the Discoveries page loads
  nothing from other hosts. In dark theme the logos sit on a light chip.
- Summary and Technical reports, with a "Print / Save as PDF" button.
- An About dialog with the web, scanner, nuclei, template, testssl.sh,
  retire.js and DB-IP versions. "Copy system info" copies versions and
  counts for a bug report (no domains, IP addresses or emails). "Check for
  updates" asks GitHub for the latest release only when you click it, and
  says why when the check fails.
- A Change password form in Settings. Changing the password signs out
  every other session.

### Changed

For anyone who ran a pre-release build:

- The default database name is `vulwall`.
- The scan schedule moved from `subscription_settings` to `scan_settings`.
- The web UI and the Jaeger UI listen on `127.0.0.1` only. To reach VulWall
  from other machines, put a reverse proxy in front of it (see "Exposing
  VulWall" in the README).
- The keys that sign login cookies moved to a web-only volume (`web-keys`).
  Everyone is signed out once after the upgrade.
- Base images, compose images and GitHub Actions are pinned by digest or
  commit SHA, and retire.js is installed with `npm ci` from a lock file.
- UI text uses sentence case and no em or en dashes. Uppercase is kept for
  the wordmark and solid severity chips; an em dash still marks an empty
  value in tables. The onboarding tour and the summary report no longer
  promise alerts or continuous monitoring.

### Removed

- The scanner's `POST /api/scans` API (`API_PORT`, `NIGHTWATCH_API_KEY`) and
  scan-completion webhook (`DASHBOARD_WEBHOOK_URL`,
  `DASHBOARD_WEBHOOK_SECRET`).
- Honeycomb-specific tracing settings (`HONEYCOMB_API_KEY`).
- Per-service scanner binaries, Dockerfiles and compose files.
- The audit log. Nothing reads or writes `audit_logs` any more; an existing
  collection is safe to drop.
- Shared report links, including the public `/shared-reports/{token}` page
  and `SHARED_LINKS_ENABLED`. Old links return 404. To share a report, save
  it as a PDF. An existing `shared_links` collection is safe to drop.
- The feature-access layer: trends and finding suppression are always on.
- The Settings "Preferences" tab. The welcome tour still opens on the first
  visit to the dashboard.

### Security

- First-run setup needs a token. Without it, `/setup` returns 404. The
  install script writes a random `SETUP_TOKEN` to `.env` (an existing one is
  kept) and prints the setup link from it; without one, the web container
  prints a new link at each start.
- Login attempts are counted before the password check, with a limit per
  IP address and a limit of 20 attempts per 15 minutes per account.
  Concurrent BCrypt checks are capped at one per CPU core.
- Logging out or changing the password ends the session everywhere (a
  security stamp in the auth cookie).
- Reference links in reports accept only `http` and `https` URLs.
- Every scanner, including the DNS zone-transfer (AXFR) check, refuses
  private and reserved addresses unless `ALLOW_PRIVATE_TARGETS=true`.
- Coverage values are stored as `$literal`, so a value that starts with `$`
  is not evaluated by MongoDB.
- `MongoDB.Driver` 3.14.1, which pulls fixed Snappier and SharpCompress
  versions (GHSA-pggp-6c3x-2xmx, GHSA-6c8g-7p36-r338).
- The web app logs request paths without control characters, cut at 200
  characters, and logs requests for missing pages at Debug only.
- The install script downloads over HTTPS only, also after redirects
  (`VULWALL_ALLOW_HTTP=1` allows an `http://` `VULWALL_BASE_URL` for local
  testing), never passes `SETUP_TOKEN` on a command line that other local
  users could read, and makes `.env` readable by its owner only.
- `vulwall uninstall` refuses the home directory (also through a symlink),
  any directory above it, and any directory the installer did not create.
- The release compose file pins the images by digest, and each release image
  has a signed build provenance attestation
  (`gh attestation verify oci://ghcr.io/vulwall/web:<version> --owner VulWall`).
- The `dead_letter` stream is capped at about 10,000 entries.

# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First open-source, self-hosted release, under the MIT License.

### Added

- `docker compose up -d` installs the full stack: MongoDB, Redis, the scanner
  and the web app. Configuration in `.env`; only `ANTHROPIC_API_KEY` is
  suggested.
- The scanner runs as one binary (`nightwatch`) in one image
  (`ghcr.io/vulwall/scanner`) with pinned, checksum-verified nuclei,
  testssl.sh and retire.js. It runs as a non-root user.
- On-demand scans are queued in MongoDB (`scans.status = "queued"`) and
  picked up by the scanner; no HTTP API between web app and scanner.
- Findings store the scanners' own `remediation` and `references`, so they
  are readable without the AI knowledge base.
- Free DB-IP Lite country and ASN databases for IP geolocation, downloaded
  on start.
- Optional OpenTelemetry tracing to any OTLP backend, with a Jaeger profile
  in the compose file.
- CI (build, vet, test), multi-arch image releases (amd64, arm64) and
  Dependabot.
- A Change password form in Settings. Changing the password signs out every
  other session.
- Country flags (flag-icons 7.6.0, MIT) and logos for AWS, Azure, Google
  Cloud, Fastly, Cloudflare, DigitalOcean, Akamai and Oracle (simple-icons
  11.15.0, CC0) ship with the web app, so the Discoveries page needs no
  external host. Unknown providers keep the generic icon. In dark theme the
  logos sit on a light chip so dark brand marks stay visible.
- The install script checks the host before it changes anything: it stops
  on Windows shells (use WSL 2), on 32-bit systems and on CPUs that MongoDB
  cannot run on (no AVX on x86-64; older than ARMv8.2-A on ARM, such as the
  Raspberry Pi 4). `VULWALL_SKIP_CPU_CHECK=1` skips the CPU check. It warns
  when Docker has less than 2 GB of memory or the disk less than 5 GB free.
- On Linux, the install script offers to install Docker with Docker's
  official script, to start a stopped Docker daemon, and to install a
  missing Compose plugin. It asks on the terminal first and uses `sudo` only
  for these steps; `VULWALL_INSTALL_DOCKER=1` agrees without asking.
- When port 8080 is in use by another program, the install script picks a
  free port from 8081 to 8099 and saves it as `VULWALL_PORT` in `.env`.
- When a container keeps crashing during the install, the script stops at
  once and shows its last log lines, with CPU advice when MongoDB stops with
  an illegal instruction. It also waits for the scanner to become healthy,
  and warns with hints about outbound access when it does not.
- Over SSH, the install script prints the `ssh -L` command that opens the
  web UI from your own computer.
- The install script saves a locally edited `docker-compose.yml` as
  `docker-compose.yml.bak.<time>` before it replaces the file.
- The `vulwall` command, installed by the install script into the install
  directory (and optionally linked into `~/.local/bin`): `status`, `logs`,
  `upgrade`, `backup`, `restore`, `reset-admin`, `doctor`, `uninstall` and
  `version`. It is a release asset, checked against `SHA256SUMS` like the
  other files.

### Changed

- The AI knowledge base is optional: without `ANTHROPIC_API_KEY` the scanner
  skips it.
- Default database name is `vulwall`.
- The web UI is published on `127.0.0.1` only. To reach it from other
  machines, use a reverse proxy; see "Exposing VulWall" in the README.
- The web image cross-compiles for arm64 instead of running the .NET SDK
  under emulation.
- Base images, compose images and GitHub Actions are pinned by digest or
  commit SHA. retire.js and its dependencies are pinned in
  `scanner/docker/retire/package-lock.json` and installed with `npm ci`.
- `MongoDB.Driver` 3.14.1.

### Security

- First-run setup needs a token. The web container prints the setup link
  once at startup (`docker compose logs web`); without the token, `/setup`
  returns 404. `SETUP_TOKEN` sets a fixed token for unattended installs.
- Password attempts on login and shared reports are counted before the
  password check, so parallel requests can no longer get past the limit.
  Login also has an account-wide limit of 20 attempts per 15 minutes, and
  concurrent BCrypt checks are capped at one per CPU core.
- The keys that sign login cookies are stored on a web-only volume
  (`web-keys`), not in the MongoDB database the scanner shares. Everyone is
  logged out once after the upgrade.
- Logging out ends the session everywhere: the auth cookie carries a
  security stamp that logout and password changes rotate.
- Reference links in the technical report accept only `http` and `https`
  URLs, as the finding page already did.
- The shared report's Print button works under the Content Security Policy.
- The Jaeger UI is published on `127.0.0.1` only.
- The DNS zone-transfer (AXFR) check uses the same public-IP guard as the
  other scanners, so a target's nameserver records cannot make the scanner
  connect to private addresses unless `ALLOW_PRIVATE_TARGETS=true`.
- `MongoDB.Driver` 3.14.1 pulls fixed Snappier and SharpCompress versions
  (GHSA-pggp-6c3x-2xmx, GHSA-6c8g-7p36-r338).
- The install script adds a random `SETUP_TOKEN` to `.env` when none is
  set and prints the setup link from it. It no longer reads the link from
  `docker compose logs web`, where a request from anyone could plant a fake
  link and terminal escape sequences. A `SETUP_TOKEN` you set is kept.
- The web app logs request paths without control characters, cut at 200
  characters, and logs requests for missing pages (404) at Debug only.
- The install script downloads over HTTPS only, also after redirects
  (`VULWALL_ALLOW_HTTP=1` allows an `http://` `VULWALL_BASE_URL` for local
  testing), and quotes the install directory in the commands it prints.
- The release compose file pins the scanner and web images by digest, and
  each release image has a signed build provenance attestation
  (`gh attestation verify oci://ghcr.io/vulwall/web:<version> --owner VulWall`).

### Fixed

- A scan closed by the idle timeout no longer marks findings as resolved:
  that timeout fires only when the pipeline has not drained. When discovery
  cannot fully check one domain asset (the domain does not exist, too many DNS
  lookups failed, or subdomain enumeration failed), only that domain's
  findings stay open; the other assets of the scan are reconciled as usual.
  A domain that seems not to exist is checked against public resolvers first
  (`DNS_RECHECK_RESOLVERS`, default `1.1.1.1,8.8.8.8`, `off` to disable). A
  scan resolves every open finding it did not see, so a finding left open by
  a partial scan is resolved by the next scan that checks its asset. Scans
  record `completion_reason`, `findings_reconciled`, `degraded_assets` and
  `unchecked_finding_ids`. The Scans page shows such a scan as "partial scan"
  with the number of affected assets, the Assets page notes the affected
  domain ("Domain does not resolve"), and a scan comparison lists its
  findings as not checked instead of resolved.
- Domain discovery no longer retries subdomains that cleanly do not exist
  (NXDOMAIN); only timeouts, SERVFAIL and refused lookups are retried. This
  cuts several minutes from domains with many stale passive-source names.
- A scan that was running when the scanner restarted no longer marks
  findings as resolved. At startup the scanner closes it as `failed` with
  `status_reason: "interrupted_by_restart"`; the Scans page shows
  "Interrupted by restart", and the next scan compares against the last
  complete scan.
- After a restart, the scanner drops the unfinished stream work of the
  previous process. Before, that work stayed pending forever, and every later
  scan could finish only by the 15-minute idle timeout.
- A stream message that makes a scanner component panic is logged with a
  stack trace and skipped instead of crashing the scanner. Work cut off by
  shutdown is no longer acknowledged as done.
- A scan that cannot start during scanner shutdown is closed as `failed`
  right away instead of staying `running`.
- A failed AI executive summary is retried after 5 and 30 minutes (3
  attempts in total). Scans that finished before `ANTHROPIC_API_KEY` was set
  get a summary once it is set, if they are less than 7 days old.
- The "Scan now" button no longer queues a second scan while an older one is still
  waiting for the scanner.

### Removed

- The scanner's `POST /api/scans` API (`API_PORT`, `NIGHTWATCH_API_KEY`) and
  scan-completion webhook (`DASHBOARD_WEBHOOK_URL`, `DASHBOARD_WEBHOOK_SECRET`).
- Honeycomb-specific tracing settings (`HONEYCOMB_API_KEY`).
- Per-service scanner binaries, Dockerfiles and compose files.

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
- Hosting logos for Hetzner, OVH, Vultr, Scaleway, Alibaba Cloud, IBM Cloud,
  Vercel, Netlify, Heroku and GitHub (simple-icons 11.15.0), matched from
  the DB-IP ASN organization name. Linode addresses show the Akamai logo.
- The Discoveries page shows the "IP geolocation by DB-IP" attribution that
  the DB-IP Lite license (CC BY 4.0) requires.
- Settings → Scan schedule: turn scheduled scans off, or run them daily,
  weekly or monthly at a time in a chosen time zone (stored as a UTC cron
  in `scan_settings`). The Settings page, sidebar and Scans page show the
  next scan. The scanner reloads schedules every 5 minutes instead of every
  hour, and keeps the current schedules when the reload fails.
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
- An About dialog, opened from the version line in the sidebar footer. It
  shows the web and scanner versions, the nuclei, templates, testssl.sh,
  retire.js and DB-IP versions, links and credits. "Copy system info"
  copies versions and counts for a bug report (no domains, IP addresses or
  emails). "Check for updates" asks GitHub for the latest release, only
  when you click it. The scanner writes its versions to the `system_info`
  collection at start and every 5 minutes.
- Adding an asset or pressing Scan now while a scan runs queues one
  follow-up scan that starts right after it and scans every asset there is
  then. Only one scan waits per organization (a unique partial index on
  `scans`); further requests say a follow-up is already queued.

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
- The sidebar footer shows "VulWall <version> · MIT" with a link to the
  GitHub repository. Release images set the version from the tag
  (`VULWALL_VERSION` build argument); other builds show "dev".
- nuclei runs without `-silent`, with `-nc -duc`. The scanner reads its log
  to tell a finished run from one that dropped the target.
- UI labels and eyebrows use sentence case; uppercase is kept for the
  wordmark and solid severity chips. The onboarding tour and the summary
  report no longer promise alerts or continuous monitoring.
- CI runs the MongoDB- and Redis-backed scanner tests and lints the
  workflow files with actionlint.
- The FAQ and the configuration page say which lookups
  `DNS_RECHECK_RESOLVERS` covers: root domains, known subdomains and SPF,
  DMARC, MX and NS records.
- Sidebar bottom: everything is left-aligned with the nav items. The active
  nav item has a white tint (no orange background) and keeps the orange bar.
  The "Next scan" card is smaller and shows the scheduled day and time next
  to its label. The organization name and email truncate with a tooltip.
  About, theme and log out are icon buttons; the "VulWall <version> · MIT"
  footer line is gone (the version stays in the About dialog).
- The About dialog is 720px wide; its "Built with" list has three columns
  on wide screens, two on medium screens and one on phones.
- More UI text uses sentence case: onboarding tour titles, the "False
  positive" and "Accepted risk" labels, page titles, report headings, error
  pages, dialogs and buttons. The design skill no longer says eyebrow labels
  are uppercase.
- nuclei scans domains and subdomains by hostname instead of the resolved
  IP, so TLS SNI and the Host header reach sites behind a CDN, WAF or
  virtual host. Every address of the name must be public before the run
  (else coverage `error`); `-lna` stays on. Open ports are still scanned by
  IP and port.

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
- `install.sh` and the `vulwall` helper no longer pass `SETUP_TOKEN` on the
  `sudo env` command line, where other local users could read it. A token
  from the environment is written to `.env` instead.
- `install.sh` makes an existing `.env` readable by its owner only.
- `vulwall uninstall` refuses the home directory (also through a symlink),
  any directory above it, and a directory the installer did not create.
- Coverage values (target, error, finding titles) are stored as
  `$literal` in the update pipeline, so a value that starts with `$` is
  not evaluated.
- The `dead_letter` stream is capped at about 10,000 entries.

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
- The organization's scan schedule moved from `subscription_settings` to
  `scan_settings` (`ScanSettings` in the web app and the scanner).
- A scan now marks a finding resolved only on positive evidence, never
  because data is missing. Before, a drained scan resolved every open finding
  it did not see, so a subdomain lost to a DNS hiccup or to subfinder
  variance, a filtered port, a scanner error, a disabled asset or a lost
  message resolved unfixed findings, which then came back. Now a finding is
  resolved as `not_reproduced` only when its host was found again, the
  scanner that reported it completed on that host and did not report it, or
  as `host_no_longer_found` when its host was confirmed gone in 3 scans in a
  row. Every scanner reports per-host coverage (new `scan_coverage`
  collection, kept 90 days), findings record `resolution_reason`, and scans
  count `stats.unchecked_findings`. Degraded assets are information only.
- Domain discovery re-checks the subdomains earlier scans found, also when
  subfinder misses them or fails, and asks the public resolvers before it
  treats a known name as gone.
- A stream message whose handler fails (for example a Redis or MongoDB
  error) is retried 3 times and then moved to the `dead_letter` stream,
  instead of being acknowledged and lost. Scanners no longer skip a finding
  they failed to publish.
- A scanner no longer reports coverage `ok` for a check that did not
  complete, so an unfixed finding is not resolved:
  - testssl.sh: a non-zero exit, a JSON file without a numeric `scanTime`,
    or a `scanProblem`/`FATAL` entry is `error`.
  - nuclei: a non-zero exit, no "Scan completed" in the log, `[FTL]`, a
    "Skipped <target> from target list" line, or a target root that answers
    403, 429, 5xx or a WAF challenge after the run is `error`.
  - Header and JS checks: `error` when neither http nor https answered, or
    when an answer is a block or WAF challenge (403, 429, 5xx,
    `cf-mitigated`, `x-amzn-waf-action`, known challenge pages). A JS file
    served as a challenge page counts as not downloaded.
  - Email check: a nameserver that did not resolve, or an AXFR attempt that
    timed out before the first record, is `error`.
- The header, email and JS scanners deduplicate findings by
  `(finding_type, title)`, the key ingestion uses, so a finding that is
  still present is always in `reported`.
- Coverage `reported` keys no longer get stored twice (field order in
  `$setUnion`).
- `vulwall reset-admin` writes the new `.env` before it stops the web app,
  and keeps the old token if deleting the admin fails.

### Removed

- The scanner's `POST /api/scans` API (`API_PORT`, `NIGHTWATCH_API_KEY`) and
  scan-completion webhook (`DASHBOARD_WEBHOOK_URL`, `DASHBOARD_WEBHOOK_SECRET`).
- Honeycomb-specific tracing settings (`HONEYCOMB_API_KEY`).
- Per-service scanner binaries, Dockerfiles and compose files.
- The audit log: the `[AuditLog]` filter, the dashboard "Recent activity"
  card, and the scanner's `system_audit_logs` stream and audit ingestion
  slice. Nothing writes or reads the `audit_logs` collection any more; an
  existing one is left in place and is safe to drop.
- The feature-access layer (`IFeatureAccessService`, `FeatureAccess`): trends
  and finding suppression are always on. Shared report links stay behind
  `SHARED_LINKS_ENABLED`.

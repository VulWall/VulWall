# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First open-source, self-hosted release.

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

### Changed

- The AI knowledge base is optional: without `ANTHROPIC_API_KEY` the scanner
  skips it.
- Default database name is `vulwall`.

### Removed

- The scanner's `POST /api/scans` API (`API_PORT`, `NIGHTWATCH_API_KEY`) and
  scan-completion webhook (`DASHBOARD_WEBHOOK_URL`, `DASHBOARD_WEBHOOK_SECRET`).
- Honeycomb-specific tracing settings (`HONEYCOMB_API_KEY`).
- Per-service scanner binaries, Dockerfiles and compose files.

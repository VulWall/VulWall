---
title: Add a scanner
description: How to add a new active scanner to VulWall's pipeline.
---

A scanner is a component of the `nightwatch` binary. It reads targets from a Redis stream and
publishes findings to another stream. It never touches MongoDB. Read
[How it works](/docs/how-it-works/) first. The full guide, with code, is
[`scanner/docs/ADDING_SERVICES.md`](https://github.com/VulWall/VulWall/blob/main/scanner/docs/ADDING_SERVICES.md).
The `js_dependency_scanner` and `http_header_scanner` packages are good examples to copy.

## Layout

```text
scanner/src/internal/active_recon/<scanner_name>/
├── constants.go      # consumer group name
├── models.go         # scanner-specific models (optional)
├── service.go        # orchestration: call the scanner, convert and publish findings
├── consumer.go       # Redis consumer
└── scanner/          # the scanning logic, with no Redis or MongoDB
    └── scanner.go
```

Keep the scanning logic in the `scanner/` package so that you can test it without
infrastructure.

## Steps

1. **Consumer group.** Define a group name such as `my_scanner_service` in `constants.go`.
2. **Consume.** Most scanners read `domain_scan_triggers`. Scanners of open ports also read
   `port_scan_triggers`. Create the group from the latest message (`$`), with
   `CreateConsumerGroupFromLatest`.
3. **Publish findings.** Convert results to `shared.SecurityFinding`, set `Source` to a short
   lowercase name, and publish to `shared.StreamSecurityFindings`. Skip jobs without an
   `org_id`.
4. **Tracing.** Extract the trace context from each message you consume, and inject it into each
   finding you publish.
5. **Register the component** in `consumers()` in `src/cmd/nightwatch/main.go`, and add its group
   to `createConsumerGroups()`.
6. **Scan completion.** Add the (stream, group) pair to `scanPipelineGroups()` in
   `src/internal/scan_coordinator/pipeline.go`, and to `TestScanPipelineGroups`. If you forget
   this, scans are marked done before your scanner has finished.
7. **Registry.** Add the component to
   [`scanner/docs/SERVICE_REGISTRY.md`](https://github.com/VulWall/VulWall/blob/main/scanner/docs/SERVICE_REGISTRY.md).
8. **External tools.** If the scanner runs a command-line tool, install a pinned version with a
   checksum check in `scanner/Dockerfile`. The image runs as a non-root user.
9. **Settings.** Read settings with `config.GetEnv*`. Add the ones users should set to the root
   `.env.example` and `docker-compose.yml`.

Scanners send real traffic to real systems. Do not add checks that change data, try to log in
with guessed passwords, or can take a service down.

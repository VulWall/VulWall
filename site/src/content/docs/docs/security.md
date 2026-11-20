---
title: Security
description: How to report a vulnerability in VulWall, and the rules for using it.
---

## Report a vulnerability

Report security vulnerabilities in VulWall **privately**, through GitHub:

1. Open [Report a vulnerability](https://github.com/VulWall/VulWall/security/advisories/new)
   (the repository's **Security** tab).
2. Describe the issue, the affected version or commit, and the steps to reproduce it. A proof of
   concept helps.

Do not open a public issue, pull request or discussion about a vulnerability until a fix is
released.

You can expect an acknowledgement within 7 days. We keep you informed while we work on a fix,
agree on a disclosure date with you, and credit you in the advisory unless you prefer to stay
anonymous.

Security fixes go into the latest release. Please upgrade to it before you report an issue.

### Scope

In scope: the code in the repository (`scanner/`, `web/`), the container images published as
`ghcr.io/vulwall/*` and the default `docker-compose.yml`.

Out of scope: vulnerabilities in third-party tools that VulWall runs (nuclei, testssl.sh,
retire.js, MongoDB, Redis). Report those to their maintainers. Findings that VulWall reports
about *your* systems are not vulnerabilities in VulWall.

The full policy is in
[SECURITY.md](https://github.com/VulWall/VulWall/blob/main/SECURITY.md).

## Scan only what you are allowed to scan

VulWall sends active network traffic: port scans, TLS handshakes and vulnerability probes.
Scanning systems without the owner's permission can be illegal in your country, and it can break
your hosting provider's terms of service.

Add only domains and IP addresses that you own or that you have written permission to test. You
alone are responsible for how you use VulWall. The software comes with no warranty; see the
[license](/docs/license/).

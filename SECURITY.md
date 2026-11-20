# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub:

1. Go to https://github.com/VulWall/VulWall/security/advisories/new
   (the repository's **Security** tab → **Report a vulnerability**).
2. Describe the issue, the affected version or commit, and the steps to
   reproduce it. A proof of concept helps.

Do not open a public issue, pull request or discussion for a vulnerability
until a fix is released.

You can expect an acknowledgement within 7 days. We will keep you informed
while we work on a fix, agree a disclosure date with you, and credit you in the
advisory unless you prefer to stay anonymous.

## Supported versions

Security fixes go into the latest release. Please upgrade to it before you
report an issue.

## Scope

In scope: the code in this repository (`scanner/`, `web/`, `install.sh`,
the `vulwall` helper), the container
images published as `ghcr.io/vulwall/*`, and the default `docker-compose.yml`
configuration.

Out of scope: vulnerabilities in third-party tools that VulWall runs (nuclei,
testssl.sh, retire.js, MongoDB, Redis). Report those to their maintainers.
Findings that VulWall reports about *your* systems are not vulnerabilities in
VulWall.

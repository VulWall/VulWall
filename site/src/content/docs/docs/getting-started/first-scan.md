---
title: Your first scan
description: Create the admin account, add a domain and run a scan.
---

## 1. Create the admin account

Open the setup link from the installer, or from
`docker compose logs web | grep "First-run setup" | tail -1`. Enter your email address, a
password and the name of your organization.

VulWall has one admin account. After setup, `/setup` is closed and you sign in at `/login`. You
can change the password later in **Settings**.

## 2. Add a domain or IP address

Go to **Assets** and add a domain you own, for example `example.com`, or an IP address. VulWall
starts a scan of a new asset right away.

:::caution
Add only assets that you own or that you have written permission to test.
:::

The scanner skips private and internal IP ranges unless you set `ALLOW_PRIVATE_TARGETS=true`.

## 3. Watch the scan

The **Scans** page shows the scan status. A scan goes through these stages:

1. **Discovery.** VulWall finds subdomains of your domains and resolves them to IP addresses, then
   scans the TCP ports of each IP address.
2. **Checks.** The scanners check every domain, subdomain and open port they get: nuclei,
   testssl.sh, retire.js, the HTTP security header check and the email security check.
3. **Done.** The scan is marked done when every scanner has finished its work.

How long a scan takes depends on how many subdomains and open ports VulWall finds.
`docker compose logs -f scanner` shows what the scanner is doing.

## 4. Read the results

- **Discoveries**: subdomains, IP addresses, open ports and services, with the country, network
  owner, cloud provider and WAF of each.
- **Dashboard** and **Recommendations**: the problems VulWall found, by severity (Critical, High,
  Medium, Low, Info), with the scanner's description, remediation advice and references. With an
  [Anthropic API key](/docs/configuration/ai/), you also get AI-written business and technical
  guidance for each finding type.
- **Reports**: a summary report and a technical report.

When a later scan no longer detects a finding, VulWall marks it as resolved. If it comes back, it
is opened again.

## Scheduled scans

VulWall scans all enabled assets once a week. The schedule is picked at random on the first
start, and the **Scans** page shows it. You can also start a scan at any time with **Scan now**.

---
title: Your first scan
description: Create the admin account, add a domain and run a scan.
---

## 1. Create the admin account

Open the setup link that the installer printed. To make it again, get the token with
`grep SETUP_TOKEN .env` in the install directory and open
`http://localhost:8080/setup?token=<token>`. If the installer picked another port, or you set
`VULWALL_PORT`, use that port; `~/vulwall/vulwall status` shows the URL. If you installed from the repository without a
`SETUP_TOKEN`, see [Open the setup page](/docs/getting-started/manual-install/#open-the-setup-page).
Enter your email address, a password and the name of your organization.

VulWall has one admin account. After setup, `/setup` is closed and you sign in at `/login`. You
can change the password later in **Settings**.

## 2. Add a domain or IP address

Go to **Assets** and add a domain you own, for example `example.com`, or an IP address. Adding an
asset does not start a scan. After you add it, VulWall offers **Scan now**. Add all your assets
first if you like: a scan covers every enabled asset when it starts.

:::caution
Add only assets that you own or that you have written permission to test.
:::

The scanner skips private and internal IP ranges unless you set `ALLOW_PRIVATE_TARGETS=true`.

## 3. Start the scan

Click **Scan now** after you add an asset, or on the **Scans** page. The **Scans** page shows the
scan status. A scan goes through these stages:

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

VulWall scans all enabled assets on the schedule in **Settings → Scan schedule**. Until you
change it, that is once a week at a random time on a weekend night (UTC), picked on the first
start. You can make it daily, weekly or monthly at a time in your time zone, or turn it off. The
time zone is your browser's; the page shows which one it uses. The scanner picks up a change
within 5 minutes. The sidebar and the **Scans** page show when the next
scan starts. You can also start a scan at any time with **Scan now**.

Adding an asset never starts a scan: a new asset is scanned by the next scan, from **Scan now** or
the schedule. A scan covers every enabled asset when it starts.

Only one scan runs at a time. While a scan is queued or running, **Scan now** is turned off; you
can start a new scan when it finishes. If the schedule comes up while a scan is running, VulWall
queues the scheduled scan and starts it as soon as the current one finishes. Only one scan waits at
a time.

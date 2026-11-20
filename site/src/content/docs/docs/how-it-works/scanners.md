---
title: Scanners
description: What each VulWall scanner checks.
---

## Discovery

### Subdomains

[subfinder](https://github.com/projectdiscovery/subfinder) finds subdomains of your domains in
public passive sources, such as certificate transparency logs. VulWall keeps only names that
resolve, and records the IP addresses of each one over time.

### Ports

A TCP connect scan of about 80 common ports on each IP address: remote access (SSH, RDP, VNC,
WinRM, Telnet), file transfer, mail, DNS, web servers, databases and similar services. VulWall
records each open port and the service on it. IP addresses that belong to a CDN are skipped.

## Vulnerability scanners

### nuclei

[nuclei](https://github.com/projectdiscovery/nuclei) runs community templates against your
domains, subdomains and open ports. By default VulWall runs templates with these tags: `cve`,
`vuln`, `exposure`, `misconfig`, `default-login`, `token`, `takeover`, `kev`, `xss`, `lfi`,
`ssrf`, `rce`, `sqli`, `auth-bypass`, `unauth` and `panel`. Templates tagged `intrusive`, `dos`
or `fuzz` do not run.

The templates are downloaded on the first start and updated every night.

nuclei scans a domain or subdomain by its name, as a browser reaches it, so sites behind a CDN,
WAF or shared hosting are tested too. Open ports are scanned by IP address and port, except
on the shared edge addresses of a CDN (Cloudflare, Fastly, CloudFront, Azure Front Door), which
answer only requests that name a site. There, ports 80 and 443 are left to the scan by name,
and another open port is scanned by the name that resolved to the address
(`https://shop.example.com:8443`) when it answers. A later scan does not resolve the findings of
such a run: resolve them by hand, or they close when the port stays closed for 3 scans. A CDN
edge address that you add as an IP asset gets a port scan but no nuclei scan; add the
hostnames behind it instead. The Discoveries page marks such an address as a CDN edge.

### TLS

[testssl.sh](https://testssl.sh) checks the HTTPS service (port 443) of each domain and
subdomain for known TLS vulnerabilities, such as Heartbleed, ROBOT, POODLE and SWEET32.

### Certificate expiry

VulWall's own check reads the TLS certificate of each domain and subdomain on port 443, by its
name, and of each open port that uses TLS from the start (465, 636, 993, 995, 5986, 6443 and
8443), by IP address. It only reads the certificate; it does not check whether a browser trusts
it.

- A certificate that expires within 30 days is a **medium** finding, "TLS certificate expires
  soon".
- Within 7 days it becomes **high**. The finding stays the same one, so it does not come back as
  a new finding every day; its description shows the expiry date, the days left, the subject and
  the issuer.
- An expired certificate is a **high** finding, "TLS certificate expired".

Set the limits with `CERT_EXPIRY_WARN_DAYS` and `CERT_EXPIRY_CRITICAL_DAYS` (see
[Configuration](/docs/configuration/)). The finding is resolved by the first scan that reads a
renewed certificate. A scan that cannot connect to the port, or cannot complete the TLS
handshake, leaves it open.

### JavaScript dependencies

VulWall loads your web pages, downloads the JavaScript files they include and checks them with
[retire.js](https://retirejs.github.io/retire.js/) for library versions with known
vulnerabilities.

### HTTP security headers

VulWall's own check. It reports:

- missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy` headers;
- weak values, such as an HSTS `max-age` that is too short or a CSP with `unsafe-inline` or
  `unsafe-eval`;
- CORS settings that allow any origin, reflect any origin, or allow credentials with a wildcard
  origin;
- headers that disclose software versions;
- HTTP that does not redirect to HTTPS, and a missing `security.txt`.

### Email security

VulWall's own DNS checks for each domain:

- **SPF:** missing, allows all senders (`+all`), or soft fail only (`~all`);
- **DMARC:** missing, policy `none`, or no aggregate reports;
- **DKIM:** no record found for common selectors;
- **DNS zone transfer:** a name server that allows AXFR to anyone.

## Enrichment

These add details to what discovery found. They do not create findings.

- **WAF detection:** sends a normal request and a few requests with typical attack payloads, and
  matches the responses against signatures of about 70 WAFs (ported from wafw00f).
- **Cloud provider:** matches IP addresses against the published IP ranges of AWS, Azure, Google
  Cloud and Fastly.
- **Geolocation:** country and network owner of each IP address, from the free
  [DB-IP Lite](https://db-ip.com) databases (CC BY 4.0).

## Severity

Findings have one of five severities: **Critical**, **High**, **Medium**, **Low** and **Info**.
The severity comes from the scanner that reported the finding. For a few nuclei templates whose
default severity does not match the real risk, VulWall uses its own rating; for example, an
expired TLS certificate is High.

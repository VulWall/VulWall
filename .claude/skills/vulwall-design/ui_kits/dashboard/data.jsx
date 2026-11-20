// Shared fake scan data for the NightWatch dashboard kit.
const FINDINGS = [
  { id: 1, level: 'critical', title: 'Exposed admin panel reachable on :8080', cve: null, host: 'api.acme.com', port: '8080',
    description: 'An administrative login panel is publicly reachable with no IP allow-listing. Restrict it to your VPN or office IPs, or put it behind SSO.' },
  { id: 2, level: 'critical', title: 'Database port open to the public internet', cve: null, host: 'db.acme.com', port: '5432',
    description: 'PostgreSQL is listening on a public interface. Close the port at the firewall and connect only over a private network.' },
  { id: 3, level: 'high', title: 'Outdated OpenSSL exposes the API to a known RCE', cve: 'CVE-2024-3094', host: 'api.acme.com', port: '443',
    description: 'The host advertises OpenSSL 3.0.6, which is vulnerable to a remote code execution flaw. Upgrade to 3.0.7 or later — your provider\u2019s package mirror already has it.' },
  { id: 4, level: 'high', title: 'SPF record allows any sender to spoof your domain', cve: null, host: 'acme.com', port: null,
    description: 'Your SPF record ends in +all, which lets anyone send mail as your domain. Change it to -all and publish a DMARC policy of quarantine or reject.' },
  { id: 5, level: 'medium', title: 'Missing Content-Security-Policy header', cve: null, host: 'www.acme.com', port: '443',
    description: 'No CSP header is set, leaving the site more exposed to cross-site scripting. Add a restrictive policy starting from default-src \u2018self\u2019.' },
  { id: 6, level: 'medium', title: 'TLS 1.0 still accepted on the marketing site', cve: null, host: 'www.acme.com', port: '443',
    description: 'An outdated encryption standard is still allowed. Disable TLS 1.0/1.1 and require TLS 1.2 or higher.' },
  { id: 7, level: 'low', title: 'Server version disclosed in HTTP headers', cve: null, host: 'www.acme.com', port: '443',
    description: 'The Server header reveals the exact nginx version, helping attackers target known bugs. Suppress or genericize the header.' },
  { id: 8, level: 'info', title: 'New subdomain discovered: staging.acme.com', cve: null, host: 'staging.acme.com', port: null,
    description: 'NightWatch found a subdomain not previously in your asset list. Confirm it is yours and whether it should be publicly reachable.' },
];

const ASSETS = [
  { host: 'acme.com', type: 'Apex domain', status: 'secure', findings: 1, tech: 'Cloudflare' },
  { host: 'www.acme.com', type: 'Subdomain', status: 'open', findings: 3, tech: 'nginx · React' },
  { host: 'api.acme.com', type: 'Subdomain', status: 'open', findings: 2, tech: '.NET · Kestrel' },
  { host: 'db.acme.com', type: 'Subdomain', status: 'open', findings: 1, tech: 'PostgreSQL' },
  { host: 'staging.acme.com', type: 'Subdomain', status: 'scanning', findings: 0, tech: 'Unknown' },
  { host: 'mail.acme.com', type: 'Subdomain', status: 'secure', findings: 0, tech: 'Google Workspace' },
];

Object.assign(window, { FINDINGS, ASSETS });

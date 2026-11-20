// Package demoseed builds and writes clearly labelled sample data ("Acme Demo") for product
// screenshots and demos. Every document it inserts carries demo: true, so Reset removes exactly
// what Apply added; the organization it renames gets its own values back from the demo_seed
// collection.
//
// The documents have the shapes the scanner's ingestion and scan monitor write (see
// docs/DATABASE.md), and the finding texts are the real texts of the scanners: the header
// rules come from http_header_scanner, the nuclei texts from the named templates, the testssl
// and retire.js texts from their output. Hosts use the reserved .test TLD and addresses only
// from the documentation ranges (RFC 5737).
package demoseed

import "github.com/VulWall/VulWall/scanner/src/internal/shared"

// CompanyName is the organization name the demo shows.
const CompanyName = "Acme Demo"

// scanDaysAgo are the start days of the demo scans, oldest first (one per calendar day; the
// Overview trend groups scans by day). The scan at requestedScan was started by the admin.
var scanDaysAgo = []int{38, 31, 24, 17, 10, 3}

const (
	requestedScan = 4
	latest        = -1 // findingSpec.last / host.last: still seen in the latest scan
)

type cloud struct{ provider, region, service string }

// host is a domain or subdomain (root is its asset's domain) or a user-added IP asset (root "").
type host struct {
	name    string
	root    string
	ip      string
	ports   []int
	banners map[int]string
	// portFrom is the first scan in which a port was open (default: the host's first scan).
	portFrom map[int]int
	country  string // ISO code (DB-IP Lite)
	conti    string // continent code
	isp      string // DB-IP ASN organization
	cloud    *cloud
	waf      string
	cdnEdge  string
	first    int // first scan that saw the host
	last     int // last scan that saw it, or latest
}

var rootDomains = []string{"acme-demo.test", "acme-shop.test"}

var hosts = []host{
	{name: "acme-demo.test", root: "acme-demo.test", ip: "198.51.100.10", ports: []int{80, 443},
		country: "NL", conti: "EU", isp: "Cloudflare, Inc.", waf: "Cloudflare", cdnEdge: "Cloudflare", last: latest},
	{name: "www.acme-demo.test", root: "acme-demo.test", ip: "198.51.100.11", ports: []int{80, 443},
		country: "NL", conti: "EU", isp: "Cloudflare, Inc.", waf: "Cloudflare", cdnEdge: "Cloudflare", last: latest},
	{name: "api.acme-demo.test", root: "acme-demo.test", ip: "203.0.113.20", ports: []int{443},
		country: "DE", conti: "EU", isp: "Amazon.com, Inc.", cloud: &cloud{"AWS", "eu-central-1", "EC2"}, last: latest},
	{name: "mail.acme-demo.test", root: "acme-demo.test", ip: "203.0.113.25", ports: []int{25, 443, 587, 993},
		banners: map[int]string{25: "220 mail.acme-demo.test ESMTP Postfix (Debian/GNU)"},
		country: "DE", conti: "EU", isp: "Hetzner Online GmbH", last: latest},
	{name: "vpn.acme-demo.test", root: "acme-demo.test", ip: "203.0.113.30", ports: []int{443},
		country: "DE", conti: "EU", isp: "Hetzner Online GmbH", last: latest},
	{name: "staging.acme-demo.test", root: "acme-demo.test", ip: "203.0.113.35", ports: []int{22, 80, 443, 3000},
		banners:  map[int]string{22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"},
		portFrom: map[int]int{3000: 2},
		country:  "DE", conti: "EU", isp: "Hetzner Online GmbH", last: latest},
	{name: "grafana.acme-demo.test", root: "acme-demo.test", ip: "203.0.113.40", ports: []int{443, 3000},
		country: "FI", conti: "EU", isp: "Hetzner Online GmbH", last: latest},
	{name: "jenkins.acme-demo.test", root: "acme-demo.test", ip: "192.0.2.50", ports: []int{443, 8080},
		country: "IE", conti: "EU", isp: "Amazon.com, Inc.", cloud: &cloud{"AWS", "eu-west-1", "EC2"}, last: latest},
	{name: "cdn.acme-demo.test", root: "acme-demo.test", ip: "198.51.100.12", ports: []int{80, 443},
		country: "US", conti: "NA", isp: "Fastly, Inc.", cloud: &cloud{"Fastly", "", ""}, cdnEdge: "Fastly", last: latest},
	{name: "status.acme-demo.test", root: "acme-demo.test", ip: "192.0.2.60", ports: []int{443},
		country: "NL", conti: "EU", isp: "Google LLC", cloud: &cloud{"GCP", "europe-west4", ""}, first: 3, last: latest},
	{name: "dev.acme-demo.test", root: "acme-demo.test", ip: "203.0.113.50", ports: []int{22, 80},
		banners: map[int]string{22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"},
		country: "DE", conti: "EU", isp: "Hetzner Online GmbH", last: 2},
	{name: "acme-shop.test", root: "acme-shop.test", ip: "198.51.100.20", ports: []int{80, 443},
		country: "NL", conti: "EU", isp: "Cloudflare, Inc.", waf: "Cloudflare", cdnEdge: "Cloudflare", last: latest},
	{name: "www.acme-shop.test", root: "acme-shop.test", ip: "198.51.100.21", ports: []int{80, 443},
		country: "NL", conti: "EU", isp: "Cloudflare, Inc.", waf: "Cloudflare", cdnEdge: "Cloudflare", last: latest},
	{name: "checkout.acme-shop.test", root: "acme-shop.test", ip: "192.0.2.30", ports: []int{443, 8443},
		country: "DE", conti: "EU", isp: "Amazon.com, Inc.", cloud: &cloud{"AWS", "eu-central-1", "EC2"}, last: latest},
	{name: "images.acme-shop.test", root: "acme-shop.test", ip: "192.0.2.35", ports: []int{80, 443},
		country: "DE", conti: "EU", isp: "Amazon.com, Inc.", cloud: &cloud{"AWS", "eu-central-1", "CLOUDFRONT"}, last: latest},
	// User-added IP assets: an old VPS, and an address that turns out to be a CDN edge.
	{name: "203.0.113.45", ip: "203.0.113.45", ports: []int{21, 22, 80},
		banners: map[int]string{21: "220 (vsFTPd 3.0.3)", 22: "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7"},
		country: "DE", conti: "EU", isp: "Hetzner Online GmbH", last: latest},
	{name: "198.51.100.24", ip: "198.51.100.24", ports: []int{80, 443, 8080, 8443},
		country: "NL", conti: "EU", isp: "Cloudflare, Inc.", cdnEdge: "Cloudflare", last: latest},
}

// findingSpec is one finding on one host, seen from scan first to scan last (latest: still
// open). A finding with last >= 0 was resolved (not_reproduced) by scan last+1.
type findingSpec struct {
	host        string
	source      string
	findingType string
	severity    string
	title       string
	description string
	remediation string
	references  []string
	metadata    map[string]any
	first, last int
}

const (
	srcNuclei  = "nuclei"
	srcTestssl = "testssl"
	srcJS      = "jsscanner"
	srcHeaders = "http-headers"
	srcEmail   = "email-security"
)

// sources are the scanners that run on a domain or subdomain target, in pipeline order.
var hostSources = []string{srcNuclei, srcTestssl, srcJS, srcHeaders}

func findings() []findingSpec {
	f := []findingSpec{
		// nuclei: texts from the templates' info blocks (projectdiscovery/nuclei-templates).
		nuclei("checkout.acme-shop.test", "CVE-2024-4577", "http/cves/2024/CVE-2024-4577.yaml", "http",
			shared.SeverityCritical, "PHP CGI - Argument Injection",
			"PHP CGI - Argument Injection (CVE-2024-4577) is a critical argument injection flaw in PHP.",
			"Apply the vendor-supplied patches or upgrade to a non-vulnerable version.",
			[]string{
				"https://s4e.io/tools/php-cgi-code-injection-cve-2024-4577",
				"http://www.openwall.com/lists/oss-security/2024/06/07/1",
				"https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html",
				"https://cert.be/en/advisory/warning-php-remote-code-execution-patch-immediately",
			},
			"https://checkout.acme-shop.test/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
			[]string{"cve", "cve2024", "php", "cgi", "rce", "kev", "vkev", "vuln"},
			map[string]any{"verified": true, "vendor": "php", "product": "php"}, 0, latest),
		nuclei("grafana.acme-demo.test", "CVE-2021-43798", "http/cves/2021/CVE-2021-43798.yaml", "http",
			shared.SeverityHigh, "Grafana v8.x - Arbitrary File Read",
			"Grafana versions 8.0.0-beta1 through 8.3.0 are vulnerable to a local directory traversal, allowing access to local files. The vulnerable URL path is `<grafana_host_url>/public/plugins/NAME/`, where NAME is the plugin ID for any installed plugin.",
			"Upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1.",
			[]string{
				"https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p",
				"https://nosec.org/home/detail/4914.html",
				"https://github.com/jas502n/Grafana-VulnTips",
				"https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
				"http://packetstormsecurity.com/files/165198/Grafana-Arbitrary-File-Reading.html",
			},
			"https://grafana.acme-demo.test/public/plugins/alertlist/../../../../../../../../../../../../../etc/passwd",
			[]string{"cve2021", "cve", "packetstorm", "grafana", "lfi", "vkev", "kev", "vuln"},
			map[string]any{"verified": "true", "max-request": 3, "vendor": "grafana", "product": "grafana"}, 0, latest),
		nuclei("jenkins.acme-demo.test", "CVE-2024-23897", "javascript/cves/2024/CVE-2024-23897.yaml", "javascript",
			shared.SeverityHigh, "Jenkins < 2.441 - Arbitrary File Read",
			"Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.",
			"Upgrade Jenkins to version 2.442 or later, or LTS 2.426.3 or later that disables the vulnerable file path replacement feature.",
			[]string{
				"https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314",
				"https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/",
				"https://github.com/forsaken0127/CVE-2024-23897",
			},
			"jenkins.acme-demo.test:443",
			[]string{"cve", "cve2024", "lfi", "rce", "jenkins", "js", "kev", "vkev", "vuln"},
			map[string]any{"verified": true, "max-request": 1, "vendor": "jenkins", "product": "jenkins"}, 0, 2),
		// Fixed by the latest scan: the score climbs from the two-critical cap (30) to 49.
		nuclei("staging.acme-demo.test", "CVE-2025-29927", "http/cves/2025/CVE-2025-29927.yaml", "http",
			shared.SeverityCritical, "Next.js Middleware Bypass",
			"Next.js contains a critical middleware bypass vulnerability affecting versions 11.1.4 through 15.2.2.\nAttackers may bypass middleware by sending a crafted x-middleware-subrequest header. This template\nrequires a baseline middleware redirect before accepting a bypass 200 response.",
			"Upgrade to Next.js 14.2.25 or 15.2.3 or later. Block the x-middleware-subrequest header at the edge.",
			[]string{
				"https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware",
				"https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw",
				"https://slcyber.io/assetnote-security-research-center/doing-the-due-diligence-analysing-the-next-js-middleware-bypass-cve-2025-29927/",
			},
			"https://staging.acme-demo.test/admin", []string{"cve", "cve2025", "nextjs", "middleware", "auth-bypass", "vkev", "vuln"},
			map[string]any{"verified": true, "max-request": 5, "vendor": "zeit", "product": "next.js"}, 0, 4),
		// expired-ssl is "low" in the template; the scanner re-rates it high (severity_overrides.go).
		nuclei("staging.acme-demo.test", "expired-ssl", "ssl/expired-ssl.yaml", "ssl",
			shared.SeverityHigh, "Expired SSL Certificate",
			"After an SSL certificate expires, you will no longer be able to communicate over a secure, encrypted HTTPS connection.",
			"Purchase or generate a new SSL/TLS certificate to replace the existing one.",
			[]string{"https://www.acunetix.com/vulnerabilities/web/tls-ssl-certificate-about-to-expire/"},
			"staging.acme-demo.test:443", []string{"ssl", "tls", "vuln"},
			map[string]any{"max-request": 1}, 2, latest),
		nuclei("staging.acme-demo.test", "git-config", "http/exposures/configs/git-config.yaml", "http",
			shared.SeverityMedium, "Git Configuration - Detect",
			"Git configuration was detected via the pattern /.git/config and log file on passed URLs.", "", nil,
			"https://staging.acme-demo.test/.git/config", []string{"config", "git", "exposure", "vuln"},
			map[string]any{"max-request": 1}, 0, 1),
		nuclei("mail.acme-demo.test", "weak-cipher-suites", "ssl/weak-cipher-suites.yaml", "ssl",
			shared.SeverityLow, "Weak Cipher Suites Detection",
			"A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.",
			"", []string{"https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/", "http://ciphersuite.info"},
			"mail.acme-demo.test:443", []string{"ssl", "tls", "misconfig", "vuln"},
			map[string]any{"max-request": 4}, 0, latest),
		nuclei("vpn.acme-demo.test", "deprecated-tls", "ssl/deprecated-tls.yaml", "ssl",
			shared.SeverityInfo, "Deprecated SSL/TLS Protocols - Detect",
			"The service accepts one or more deprecated SSL/TLS protocol versions: SSL 2.0, SSL 3.0, TLS 1.0 or TLS 1.1. These versions are prohibited or deprecated (RFC 6176, RFC 7568, RFC 8996) and are affected by known weaknesses such as DROWN and POODLE.",
			"Disable SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 and only allow TLS 1.2 and TLS 1.3.",
			[]string{
				"https://ssl-config.mozilla.org/#config=intermediate",
				"https://datatracker.ietf.org/doc/html/rfc6176",
				"https://datatracker.ietf.org/doc/html/rfc7568",
				"https://datatracker.ietf.org/doc/html/rfc8996",
				"https://drownattack.com/",
			},
			"vpn.acme-demo.test:443", []string{"ssl", "tls", "vuln"},
			map[string]any{"verified": true, "max-request": 4}, 0, latest),
		nuclei("grafana.acme-demo.test", "grafana-detect", "http/exposed-panels/grafana-detect.yaml", "http",
			shared.SeverityInfo, "Grafana Login Panel - Detect", "Grafana login panel was detected.", "", nil,
			"https://grafana.acme-demo.test/login", []string{"panel", "grafana", "detect", "discovery"},
			map[string]any{"max-request": 2, "vendor": "grafana", "product": "grafana", "category": "devops"}, 0, latest),
		nuclei("jenkins.acme-demo.test", "jenkins-login", "http/exposed-panels/jenkins-login.yaml", "http",
			shared.SeverityInfo, "Jenkins Login Detected", "Jenkins is an open source automation server.",
			"Ensure proper access.", []string{"https://www.jenkins.io/doc/book/security/"},
			"https://jenkins.acme-demo.test/login", []string{"panel", "jenkins", "discovery"},
			map[string]any{"max-request": 1, "vendor": "jenkins", "product": "jenkins"}, 0, latest),

		// testssl.sh (-U): LUCKY13 and SWEET32 are re-rated info (testssl_scanner/severity_overrides.go).
		testssl("vpn.acme-demo.test", "LUCKY13", shared.SeverityInfo,
			"potentially vulnerable, uses obsolete TLS CBC ciphers", "CVE-2013-0169", "CWE-310", 0, latest),
		testssl("mail.acme-demo.test", "SWEET32", shared.SeverityInfo,
			"VULNERABLE, uses 64 bit block ciphers", "CVE-2016-2183 CVE-2016-6329", "CWE-327", 0, latest),
		testssl("jenkins.acme-demo.test", "BREACH", shared.SeverityLow,
			"potentially VULNERABLE, gzip HTTP compression detected  - only supplied \"/\" tested", "CVE-2013-3587", "CWE-310", 0, latest),

		// retire.js: summaries, CVEs, CWEs and links from the retire.js repository.
		retire("www.acme-shop.test", "jquery", "1.12.4", "https://www.acme-shop.test/js/jquery-1.12.4.min.js",
			"Regex in its jQuery.htmlPrefilter sometimes may introduce XSS", "CVE-2020-11022", "GHSA-gxr4-xjj5-5px2",
			"CWE-79", ">= 1.12.0 && < 3.5.0", []string{"https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"}, 0, latest),
		retire("www.acme-shop.test", "jquery", "1.12.4", "https://www.acme-shop.test/js/jquery-1.12.4.min.js",
			"passing HTML containing <option> elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code.",
			"CVE-2020-11023", "GHSA-jpcq-cgw6-v4j6", "CWE-79", ">= 1.0.3 && < 3.5.0",
			[]string{"https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"}, 0, latest),
		retire("www.acme-shop.test", "jquery", "1.12.4", "https://www.acme-shop.test/js/jquery-1.12.4.min.js",
			"jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution",
			"CVE-2019-11358", "GHSA-6c3j-c64m-qhgq", "CWE-1321", ">= 1.1.4 && < 3.4.0",
			[]string{
				"https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/",
				"https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b",
				"https://nvd.nist.gov/vuln/detail/CVE-2019-11358",
			}, 0, latest),
		retire("www.acme-shop.test", "jquery", "1.12.4", "https://www.acme-shop.test/js/jquery-1.12.4.min.js",
			"3rd party CORS request may execute", "CVE-2015-9251", "GHSA-rmxg-73gg-4p98", "CWE-79", ">= 1.12.3 && < 3.0.0-beta1",
			[]string{
				"http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/",
				"http://research.insecurelabs.org/jquery/test/",
				"https://github.com/advisories/GHSA-rmxg-73gg-4p98",
				"https://github.com/jquery/jquery/issues/2432",
				"https://nvd.nist.gov/vuln/detail/CVE-2015-9251",
			}, 0, latest),
		retire("www.acme-demo.test", "bootstrap", "3.3.7", "https://www.acme-demo.test/assets/bootstrap.min.js",
			"XSS in data-template, data-content and data-title properties of tooltip/popover", "CVE-2019-8331", "GHSA-9v3m-8fp8-mj99",
			"CWE-79", ">= 3.0.0 && < 3.4.1",
			[]string{"https://github.com/advisories/GHSA-9v3m-8fp8-mj99", "https://github.com/twbs/bootstrap/issues/28236"}, 0, 2),
		retire("www.acme-demo.test", "bootstrap", "3.3.7", "https://www.acme-demo.test/assets/bootstrap.min.js",
			"XSS in data-container property of tooltip", "CVE-2018-14042", "GHSA-7mvr-5x2g-wfc8", "CWE-79", ">= 2.3.0 && < 3.4.0",
			[]string{"https://github.com/twbs/bootstrap/issues/20184"}, 0, 2),

		// http-headers
		header("www.acme-demo.test", "missing-csp", 0, latest),
		header("staging.acme-demo.test", "missing-csp", 0, latest),
		header("www.acme-demo.test", "missing-x-frame-options", 0, latest), // suppressed as false positive
		header("acme-demo.test", "missing-permissions-policy", 0, latest),
		header("api.acme-demo.test", "missing-hsts", 0, 1),
		header("staging.acme-demo.test", "missing-hsts", 0, latest),
		header("checkout.acme-shop.test", "missing-hsts", 0, 4),
		header("www.acme-shop.test", "missing-referrer-policy", 0, latest),
		header("status.acme-demo.test", "missing-referrer-policy", 3, latest),
		header("images.acme-shop.test", "missing-x-content-type-options", 5, latest),
		{host: "api.acme-demo.test", source: srcHeaders, findingType: "cors-wildcard-origin", severity: shared.SeverityMedium,
			title:       "CORS Allows Any Origin",
			description: "The server sets Access-Control-Allow-Origin: *, allowing any website to read responses from your application. While credentials are not included with wildcard origins, this may still expose sensitive data from unauthenticated endpoints.",
			references: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
			},
			metadata: map[string]any{"header_name": "Access-Control-Allow-Origin", "present": true, "current_value": "*",
				"url": "https://api.acme-demo.test", "issue_type": "weak-value"},
			first: 0, last: latest}, // suppressed as accepted risk
		{host: "checkout.acme-shop.test", source: srcHeaders, findingType: "header-disclosure-x-powered-by", severity: shared.SeverityInfo,
			title:       "Information disclosure via X-Powered-By header",
			description: "The X-Powered-By header is present and reveals server technology information (PHP/8.1.2). This helps attackers identify specific software versions and target known vulnerabilities.",
			references: []string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
			},
			metadata: map[string]any{"header_name": "X-Powered-By", "present": true, "current_value": "PHP/8.1.2",
				"url": "https://checkout.acme-shop.test", "issue_type": "weak-value"},
			first: 0, last: latest},

		// email-security
		{host: "acme-demo.test", source: srcEmail, findingType: "dmarc-policy-none", severity: shared.SeverityMedium,
			title:       "DMARC Policy Set to None",
			description: "The DMARC policy is set to 'none', which only monitors email authentication failures without taking action. Emails that fail SPF/DKIM checks are still delivered normally. While 'p=none' is useful for initial deployment and gathering reports, it should be upgraded to 'p=quarantine' or 'p=reject' to actively protect against email spoofing.",
			references:  []string{"https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"},
			metadata:    map[string]any{"record_value": "v=DMARC1; p=none; rua=mailto:dmarc@acme-demo.test"},
			first:       0, last: 2},
		{host: "acme-demo.test", source: srcEmail, findingType: "spf-softfail-all", severity: shared.SeverityLow,
			title:       "SPF Record Uses Soft Fail",
			description: "The SPF record uses '~all' (soft fail) instead of '-all' (hard fail). While soft fail marks unauthorized emails as suspicious, it does not instruct receiving servers to reject them outright. For stronger protection against email spoofing, consider upgrading to '-all' which causes unauthorized emails to be rejected.",
			references:  []string{"https://datatracker.ietf.org/doc/html/rfc7208#section-8.4"},
			metadata:    map[string]any{"record_value": "v=spf1 mx include:_spf.google.com ~all"},
			first:       0, last: 4},
		{host: "acme-shop.test", source: srcEmail, findingType: "missing-dmarc", severity: shared.SeverityMedium,
			title:       "Missing DMARC Record",
			description: "No DMARC (Domain-based Message Authentication, Reporting & Conformance) record was found at _dmarc.acme-shop.test. DMARC builds on SPF and DKIM to provide domain-level email authentication. Without DMARC, there is no policy instructing receiving servers how to handle emails that fail authentication checks, leaving the domain vulnerable to spoofing.",
			references:  []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
			first:       0, last: 3},
		{host: "acme-shop.test", source: srcEmail, findingType: "missing-dkim", severity: shared.SeverityLow,
			title:       "No DKIM Record Found",
			description: "No DKIM (DomainKeys Identified Mail) record was found at common selectors (default, google, selector1, selector2, k1, dkim, s1, s2, mail, dkim1, dkim2, mx, smtp, email) for this domain. DKIM cryptographically signs outgoing emails, allowing recipients to verify the message was not altered in transit. Note: DKIM selectors are domain-specific, so a record may exist at a custom selector not checked here.",
			references:  []string{"https://datatracker.ietf.org/doc/html/rfc6376"},
			first:       0, last: 4},
		{host: "acme-shop.test", source: srcEmail, findingType: "dns-zone-transfer", severity: shared.SeverityHigh,
			title:       "DNS Zone Transfer Allowed",
			description: "The following nameservers allow public DNS zone transfers (AXFR) for acme-shop.test, exposing 37 total DNS records: ns2.acme-shop.test. This gives attackers a full map of internal hostnames, staging servers, and services. Zone transfers should be restricted to authorized secondary nameservers only.",
			references:  []string{"https://datatracker.ietf.org/doc/html/rfc5936"},
			metadata:    map[string]any{"record_value": "ns2.acme-shop.test"},
			first:       0, last: 1},
	}
	return f
}

// suppression is a user decision on a finding (web app collection finding_suppressions).
type suppression struct {
	host, findingType, status, note string
	daysAgo                         int
}

var suppressions = []suppression{
	{"api.acme-demo.test", "cors-wildcard-origin", "accepted_risk",
		"Public read-only catalogue API. Responses carry no user data; reviewed with the API team.", 20},
	{"www.acme-demo.test", "missing-x-frame-options", "false_positive",
		"The CDN sets Content-Security-Policy frame-ancestors 'self' on every HTML response; the scanner saw the redirect.", 15},
}

func nuclei(host, id, path, typ, severity, name, description, remediation string, refs []string,
	matchedAt string, tags []string, info map[string]any, first, last int) findingSpec {
	return findingSpec{
		host: host, source: srcNuclei, findingType: id, severity: severity, title: name,
		description: description, remediation: remediation, references: refs,
		metadata: map[string]any{
			"template_id":       id,
			"template_path":     "/data/nuclei-templates/" + path,
			"type":              typ,
			"matched_at":        matchedAt,
			"matcher_name":      "",
			"curl_command":      "",
			"extracted_results": []string(nil),
			"author":            []string{"pdteam"},
			"tags":              tags,
			"reference":         refs,
			"nuclei_metadata":   info,
		},
		first: first, last: last,
	}
}

func testssl(host, id, severity, finding, cve, cwe string, first, last int) findingSpec {
	return findingSpec{
		host: host, source: srcTestssl, findingType: id, severity: severity,
		title: "TLS/SSL: " + id, description: finding,
		metadata: map[string]any{"test_id": id, "target": host + ":443", "cve": cve, "cwe": cwe},
		first:    first, last: last,
	}
}

func retire(host, component, version, jsURL, summary, cve, ghsa, cwe, affected string, refs []string, first, last int) findingSpec {
	return findingSpec{
		host: host, source: srcJS, findingType: lower(cve), severity: shared.SeverityMedium,
		title: jsTitle(component, version, summary, []string{cve}), description: summary, references: refs,
		metadata: map[string]any{
			"component":         component,
			"version":           version,
			"js_url":            jsURL,
			"page_url":          "https://" + host,
			"cves":              []string{cve},
			"cwes":              []string{cwe},
			"affected_versions": affected,
			"references":        refs,
			"detection_method":  "filecontent",
			"github_id":         ghsa,
		},
		first: first, last: last,
	}
}

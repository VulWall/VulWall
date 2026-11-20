package demoseed

import "time"

// kbDoc has the shape kb_ingestion writes (knowledge_base, _id "kb_<finding_type>"), with the
// sections of the KB engine's response schema (enrichers/knowledge_base/prompts/response_schema.json).
// The web app shows only published entries.
type kbDoc struct {
	ID          string      `bson:"_id"`
	FindingType string      `bson:"finding_type"`
	Business    kbBusiness  `bson:"business"`
	Technical   kbTechnical `bson:"technical"`
	Metadata    kbMetadata  `bson:"metadata"`
	Model       string      `bson:"model"`
	Published   bool        `bson:"published"`
	Version     int         `bson:"version"`
	CreatedAt   time.Time   `bson:"created_at"`
	UpdatedAt   time.Time   `bson:"updated_at"`
	Demo        bool        `bson:"demo"`
}

type kbBusiness struct {
	Title    string   `bson:"title"`
	Summary  string   `bson:"summary"`
	Impact   string   `bson:"impact"`
	Urgency  string   `bson:"urgency"` // immediate, high, medium, low
	Actions  []string `bson:"actions"`
	BlogSlug string   `bson:"blog_slug"`
}

type kbTechnical struct {
	Title                    string         `bson:"title"`
	VulnerabilityExplanation string         `bson:"vulnerability_explanation"`
	RootCause                string         `bson:"root_cause"`
	Impact                   string         `bson:"impact"`
	Severity                 kbSeverity     `bson:"severity"`
	AffectedComponents       []string       `bson:"affected_components"`
	RemediationSteps         []string       `bson:"remediation_steps"`
	VerificationSteps        []string       `bson:"verification_steps"`
	CodeExamples             *kbCodeExample `bson:"code_examples"`
	BestPractices            []string       `bson:"best_practices"`
	References               []string       `bson:"references"`
	BlogSlug                 string         `bson:"blog_slug"`
}

type kbSeverity struct {
	Level         string  `bson:"level"`
	CVSSEstimate  *string `bson:"cvss_estimate"` // nil when unknown
	Justification string  `bson:"justification"`
}

type kbCodeExample struct {
	Vulnerable string `bson:"vulnerable"`
	Fixed      string `bson:"fixed"`
	Language   string `bson:"language"`
}

type kbMetadata struct {
	Components      []string `bson:"components"`
	OWASPCategory   string   `bson:"owasp_category"`
	EstimatedEffort string   `bson:"estimated_effort"` // trivial, small, medium, large
	IsExploitable   bool     `bson:"is_exploitable"`
	Tags            []string `bson:"tags"`
}

// kbModel names the writer of the sample entries; the KB engine stores the Anthropic model here.
const kbModel = "demo-seed (sample entry)"

func ptr(s string) *string { return &s }

// knowledgeBase are sample entries for the top finding types of the demo, written in the style
// of the KB engine's output.
func knowledgeBase() []kbDoc {
	return []kbDoc{
		{
			FindingType: "CVE-2024-4577",
			Business: kbBusiness{
				Title:   "Outdated PHP Lets Attackers Take Over the Checkout Server",
				Summary: "The checkout server runs a PHP version with a known flaw that lets anyone on the internet run their own commands on it. Attackers scan for this flaw automatically, and it is on the list of vulnerabilities known to be exploited in real attacks.",
				Impact:  "An attacker who controls this server can read or change the data it handles, install malware or use it to reach other systems. That can mean a data breach you must report, downtime and loss of customer trust.",
				Urgency: "immediate",
				Actions: []string{
					"Ask your developer or hosting provider to update PHP on checkout.acme-shop.test today.",
					"Until it is updated, ask them to block the vulnerable request pattern in the web server or firewall.",
					"Have them check the server for signs of a past break-in, because this flaw has been attacked since June 2024.",
				},
				BlogSlug: "php-cgi-argument-injection-business-risk",
			},
			Technical: kbTechnical{
				Title:                    "PHP-CGI Argument Injection (CVE-2024-4577)",
				VulnerabilityExplanation: "On Windows, PHP in CGI mode converts some Unicode characters (such as the soft hyphen 0xAD) into a hyphen under certain code pages (\"Best-Fit\" mapping). A query string such as ?%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input is then passed to php-cgi as command-line options, which bypasses the fix for CVE-2012-1823.",
				RootCause:                "php-cgi escapes the hyphen before it parses the query string, but Windows converts the soft hyphen into a hyphen after that check.",
				Impact:                   "Unauthenticated remote code execution with the rights of the web server process.",
				Severity:                 kbSeverity{Level: "critical", CVSSEstimate: ptr("9.8"), Justification: "Unauthenticated, network-reachable, public exploit code, listed in CISA KEV."},
				AffectedComponents:       []string{"PHP 8.1 < 8.1.29", "PHP 8.2 < 8.2.20", "PHP 8.3 < 8.3.8", "PHP 5.x and 7.x (end of life, all versions)"},
				RemediationSteps: []string{
					"Upgrade PHP to 8.1.29, 8.2.20, 8.3.8 or later.",
					"Run PHP through PHP-FPM or mod_php instead of php-cgi where possible.",
					"As a stop-gap, add a rewrite rule that rejects query strings that start with %AD.",
				},
				VerificationSteps: []string{
					"Run php -v on the server and confirm the patched version.",
					"Run the next VulWall scan and check that the finding is resolved.",
				},
				CodeExamples: &kbCodeExample{
					Vulnerable: "Action application/x-httpd-php \"/php-cgi/php-cgi.exe\"",
					Fixed:      "RewriteCond %{QUERY_STRING} ^%ad [NC]\nRewriteRule .? - [F,L]",
					Language:   "apache",
				},
				BestPractices: []string{
					"Keep PHP on a supported branch and apply security releases within days.",
					"Do not expose php-cgi directly; prefer PHP-FPM behind the web server.",
				},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
					"https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html",
				},
				BlogSlug: "remediating-php-cgi-cve-2024-4577",
			},
			Metadata: kbMetadata{Components: []string{"PHP", "php-cgi", "Windows"}, OWASPCategory: "A06", EstimatedEffort: "small", IsExploitable: true,
				Tags: []string{"rce", "php", "cve", "kev"}},
		},
		{
			FindingType: "CVE-2021-43798",
			Business: kbBusiness{
				Title:   "Monitoring Dashboard Leaks Files From Its Server",
				Summary: "The Grafana dashboard at grafana.acme-demo.test has a known flaw that lets anyone read files from the server without logging in. Those files can include passwords and keys for other systems.",
				Impact:  "Stolen configuration files can give an attacker database passwords or access tokens, which lets them move from the dashboard to systems that hold customer or business data.",
				Urgency: "high",
				Actions: []string{
					"Ask whoever runs Grafana to update it to a supported version this week.",
					"Make the dashboard reachable only through your VPN or office network.",
					"After the update, change the passwords and keys that the Grafana server stores.",
				},
				BlogSlug: "grafana-file-read-business-risk",
			},
			Technical: kbTechnical{
				Title:                    "Grafana 8.x Path Traversal in Plugin Assets (CVE-2021-43798)",
				VulnerabilityExplanation: "The /public/plugins/<plugin-id>/ handler joins the requested path to the plugin directory without cleaning it, so ../ sequences read arbitrary files such as /etc/passwd, grafana.ini or grafana.db.",
				RootCause:                "Missing path normalization in the static file handler for installed plugins.",
				Impact:                   "Unauthenticated arbitrary file read with the rights of the Grafana process, including secrets in grafana.ini and the SQLite database.",
				Severity:                 kbSeverity{Level: "high", CVSSEstimate: ptr("7.5"), Justification: "Unauthenticated file read with public exploits; listed in CISA KEV."},
				AffectedComponents:       []string{"Grafana 8.0.0-beta1 through 8.3.0"},
				RemediationSteps: []string{
					"Upgrade Grafana to 8.3.1, 8.2.7, 8.1.8 or 8.0.7, or to a current release.",
					"Rotate the secret_key and the data source credentials stored in Grafana.",
					"Restrict access to the Grafana port with a firewall or reverse proxy.",
				},
				VerificationSteps: []string{
					"Request /public/plugins/alertlist/../../../../../../../../etc/passwd and confirm a 404 or 400.",
					"Run the next VulWall scan and check that the finding is resolved.",
				},
				CodeExamples: &kbCodeExample{
					Vulnerable: "GET /public/plugins/alertlist/../../../../../../../../etc/passwd HTTP/1.1",
					Fixed:      "location /public/plugins/ {\n    if ($request_uri ~ \"\\.\\./\") { return 400; }\n    proxy_pass http://grafana:3000;\n}",
					Language:   "nginx",
				},
				BestPractices: []string{
					"Do not expose internal dashboards to the internet.",
					"Subscribe to the vendor's security advisories for every self-hosted tool.",
				},
				References: []string{
					"https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/",
					"https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
				},
				BlogSlug: "remediating-grafana-cve-2021-43798",
			},
			Metadata: kbMetadata{Components: []string{"Grafana"}, OWASPCategory: "A01", EstimatedEffort: "small", IsExploitable: true,
				Tags: []string{"lfi", "path-traversal", "grafana", "cve", "kev"}},
		},
		{
			FindingType: "weak-cipher-suites",
			Business: kbBusiness{
				Title:   "Mail Server Still Accepts Outdated Encryption",
				Summary: "The mail server accepts some old encryption methods next to modern ones. Most visitors use the modern ones, but the old ones should be switched off.",
				Impact:  "An attacker in a privileged network position could in theory force a weaker connection. The risk is low, but auditors and customers' security questionnaires often flag it.",
				Urgency: "low",
				Actions: []string{
					"Ask your IT contractor to switch off the old cipher suites on mail.acme-demo.test.",
					"Use the Mozilla \"intermediate\" configuration as the target.",
				},
				BlogSlug: "weak-tls-ciphers-business-risk",
			},
			Technical: kbTechnical{
				Title:                    "Weak TLS Cipher Suites Offered",
				VulnerabilityExplanation: "The server negotiates cipher suites with short keys or obsolete algorithms (for example 3DES or CBC suites without forward secrecy) when a client offers them.",
				RootCause:                "The TLS configuration still uses a legacy cipher list for compatibility with old clients.",
				Impact:                   "Makes downgrade and cryptanalytic attacks such as SWEET32 possible in theory; it does not expose data on its own.",
				Severity:                 kbSeverity{Level: "low", CVSSEstimate: ptr("3.7"), Justification: "Needs a network position and a lot of traffic; modern clients prefer strong suites."},
				AffectedComponents:       []string{"TLS configuration of mail.acme-demo.test:443 (all versions)"},
				RemediationSteps: []string{
					"Set the cipher list to the Mozilla intermediate profile.",
					"Disable 3DES, RC4 and export-grade suites.",
					"Reload the service and repeat the test.",
				},
				VerificationSteps: []string{
					"Run testssl.sh --cipher-per-proto mail.acme-demo.test:443 and confirm only strong suites remain.",
				},
				CodeExamples: &kbCodeExample{
					Vulnerable: "ssl_ciphers ALL:!aNULL;",
					Fixed:      "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers off;",
					Language:   "nginx",
				},
				BestPractices: []string{"Review TLS settings once a year against the Mozilla guidelines."},
				References:    []string{"https://ssl-config.mozilla.org/", "https://ciphersuite.info"},
				BlogSlug:      "fixing-weak-tls-cipher-suites",
			},
			Metadata: kbMetadata{Components: []string{"TLS", "nginx", "Postfix"}, OWASPCategory: "A02", EstimatedEffort: "small", IsExploitable: false,
				Tags: []string{"tls", "crypto", "configuration"}},
		},
		{
			FindingType: "missing-csp",
			Business: kbBusiness{
				Title:   "Website Lacks a Basic Defense Against Malicious Scripts",
				Summary: "The website does not tell browsers which scripts are allowed to run. This header is a safety net: if an attacker manages to inject code into a page, it stops the browser from running it.",
				Impact:  "Without it, a single flaw in the site or in a third-party script can be used to steal logins or show fake forms to your visitors.",
				Urgency: "medium",
				Actions: []string{
					"Ask your web developer to add a Content-Security-Policy header, first in report-only mode.",
					"Review the reports for two weeks, then switch the policy to enforce.",
				},
				BlogSlug: "missing-content-security-policy-business-risk",
			},
			Technical: kbTechnical{
				Title:                    "Missing Content-Security-Policy Header",
				VulnerabilityExplanation: "Responses carry no Content-Security-Policy header, so the browser runs any inline or remote script that ends up in the page.",
				RootCause:                "The web server and application set no CSP; it is not on by default in common frameworks.",
				Impact:                   "Raises the impact of any cross-site scripting or supply-chain compromise to full script execution in the visitor's session.",
				Severity:                 kbSeverity{Level: "medium", Justification: "Defense in depth: not exploitable alone, but it decides how bad an XSS becomes."},
				AffectedComponents:       []string{"www.acme-demo.test and staging.acme-demo.test (all versions)"},
				RemediationSteps: []string{
					"List the script, style and image sources the site really uses.",
					"Deploy Content-Security-Policy-Report-Only with those sources and a report endpoint.",
					"Fix or allow the violations, then send the same policy as Content-Security-Policy.",
				},
				VerificationSteps: []string{
					"curl -sI https://www.acme-demo.test | grep -i content-security-policy",
					"Run the next VulWall scan and check that the finding is resolved.",
				},
				CodeExamples: &kbCodeExample{
					Vulnerable: "# no Content-Security-Policy header",
					Fixed:      "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'\" always;",
					Language:   "nginx",
				},
				BestPractices: []string{"Avoid inline scripts so the policy can stay strict.", "Use nonces or hashes when inline code is unavoidable."},
				References: []string{
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
					"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
				},
				BlogSlug: "adding-a-content-security-policy",
			},
			Metadata: kbMetadata{Components: []string{"HTTP headers", "Frontend"}, OWASPCategory: "A05", EstimatedEffort: "medium", IsExploitable: false,
				Tags: []string{"headers", "xss", "defense-in-depth"}},
		},
	}
}

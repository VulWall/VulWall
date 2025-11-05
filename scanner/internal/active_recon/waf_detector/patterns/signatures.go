package patterns

import "regexp"

// CheckType represents the type of check to perform
type CheckType string

const (
	CheckTypeHeader  CheckType = "header"
	CheckTypeCookie  CheckType = "cookie"
	CheckTypeContent CheckType = "content"
	CheckTypeCode    CheckType = "code"
)

// Check represents a single detection check
type Check struct {
	Type    CheckType         // Type of check (header, cookie, content, code)
	Key     string            // Header/cookie name (for header/cookie checks)
	Pattern string            // Regex pattern to match
	Regex   *regexp.Regexp    // Compiled regex (populated automatically)
	Options map[string]string // Additional options (e.g., case sensitivity)
}

// WAFSignature represents a WAF detection signature
type WAFSignature struct {
	Name        string  // WAF name (e.g., "Cloudflare")
	Vendor      string  // Vendor name (e.g., "Cloudflare Inc.")
	Description string  // Description of the WAF
	Checks      []Check // Detection checks
	Priority    int     // Priority for matching (higher = check first)
}

// CompileSignatures compiles all regex patterns in signatures
func CompileSignatures(signatures []WAFSignature) error {
	for i := range signatures {
		for j := range signatures[i].Checks {
			if signatures[i].Checks[j].Pattern != "" {
				regex, err := regexp.Compile(signatures[i].Checks[j].Pattern)
				if err != nil {
					return err
				}
				signatures[i].Checks[j].Regex = regex
			}
		}
	}
	return nil
}

// AllSignatures contains all WAF detection signatures
// Ported from wafw00f Python project
var AllSignatures = []WAFSignature{
	// Cloudflare
	{
		Name:        "Cloudflare",
		Vendor:      "Cloudflare Inc.",
		Description: "Cloudflare Web Application Firewall",
		Priority:    100,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "CF-Ray", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)cloudflare`},
			{Type: CheckTypeCookie, Pattern: `__cfduid`},
			{Type: CheckTypeCookie, Pattern: `__cflb`},
			{Type: CheckTypeCookie, Pattern: `cf_clearance`},
			{Type: CheckTypeContent, Pattern: `(?i)cloudflare`},
			{Type: CheckTypeContent, Pattern: `(?i)ray\s*id`},
			{Type: CheckTypeCode, Pattern: `^(403|503)$`},
		},
	},

	// Akamai
	{
		Name:        "Akamai",
		Vendor:      "Akamai Technologies",
		Description: "Akamai Kona Site Defender",
		Priority:    95,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-Akamai-Session-Info", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-Akamai-Request-ID", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)akamai`},
			{Type: CheckTypeCookie, Pattern: `AKA_A2`},
			{Type: CheckTypeContent, Pattern: `(?i)akamai`},
			{Type: CheckTypeContent, Pattern: `(?i)reference\s*#\d+\.\w+`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// AWS WAF
	{
		Name:        "AWS WAF",
		Vendor:      "Amazon Web Services",
		Description: "AWS Web Application Firewall",
		Priority:    90,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-AMZ-ID", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-AMZN-RequestID", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-AMZN-ErrorType", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-AMZN-Trace-Id", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)aws`},
			{Type: CheckTypeContent, Pattern: `(?i)request\s*id`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Imperva Incapsula
	{
		Name:        "Imperva Incapsula",
		Vendor:      "Imperva Inc.",
		Description: "Imperva Incapsula Web Application Firewall",
		Priority:    85,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-CDN", Pattern: `(?i)incapsula`},
			{Type: CheckTypeHeader, Key: "X-Iinfo", Pattern: `.+`},
			{Type: CheckTypeCookie, Pattern: `incap_ses_`},
			{Type: CheckTypeCookie, Pattern: `visid_incap_`},
			{Type: CheckTypeContent, Pattern: `(?i)incapsula`},
			{Type: CheckTypeContent, Pattern: `(?i)incident\s*id`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Sucuri
	{
		Name:        "Sucuri",
		Vendor:      "Sucuri Inc.",
		Description: "Sucuri CloudProxy WAF",
		Priority:    80,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)sucuri`},
			{Type: CheckTypeHeader, Key: "X-Sucuri-ID", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-Sucuri-Cache", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)sucuri`},
			{Type: CheckTypeContent, Pattern: `(?i)access\s*denied.*?sucuri`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Cloudfront
	{
		Name:        "Amazon CloudFront",
		Vendor:      "Amazon Web Services",
		Description: "Amazon CloudFront CDN with WAF",
		Priority:    75,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Via", Pattern: `(?i)cloudfront`},
			{Type: CheckTypeHeader, Key: "X-Cache", Pattern: `(?i)cloudfront`},
			{Type: CheckTypeHeader, Key: "X-AMZ-CF-ID", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-AMZ-CF-POP", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)cloudfront`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Barracuda
	{
		Name:        "Barracuda",
		Vendor:      "Barracuda Networks",
		Description: "Barracuda Web Application Firewall",
		Priority:    70,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `barra_counter_session`},
			{Type: CheckTypeCookie, Pattern: `BNI__BARRACUDA_LB_COOKIE`},
			{Type: CheckTypeContent, Pattern: `(?i)barracuda`},
			{Type: CheckTypeContent, Pattern: `(?i)you\s*have\s*been\s*blocked`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// F5 BIG-IP
	{
		Name:        "F5 BIG-IP",
		Vendor:      "F5 Networks",
		Description: "F5 BIG-IP Application Security Manager",
		Priority:    65,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)big-?ip`},
			{Type: CheckTypeHeader, Key: "X-WA-Info", Pattern: `.+`},
			{Type: CheckTypeCookie, Pattern: `TS[a-f0-9]{6,8}`},
			{Type: CheckTypeCookie, Pattern: `BIGipServer`},
			{Type: CheckTypeContent, Pattern: `(?i)big-?ip`},
			{Type: CheckTypeContent, Pattern: `(?i)f5`},
			{Type: CheckTypeCode, Pattern: `^(403|406)$`},
		},
	},

	// ModSecurity
	{
		Name:        "ModSecurity",
		Vendor:      "Trustwave",
		Description: "ModSecurity Web Application Firewall",
		Priority:    60,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)mod_security`},
			{Type: CheckTypeContent, Pattern: `(?i)mod_security`},
			{Type: CheckTypeContent, Pattern: `(?i)modsecurity`},
			{Type: CheckTypeContent, Pattern: `(?i)this\s*error\s*was\s*generated\s*by\s*mod_security`},
			{Type: CheckTypeCode, Pattern: `^(403|406|501)$`},
		},
	},

	// Fortinet FortiWeb
	{
		Name:        "Fortinet FortiWeb",
		Vendor:      "Fortinet Inc.",
		Description: "Fortinet FortiWeb Web Application Firewall",
		Priority:    55,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `FORTIWAFSID`},
			{Type: CheckTypeContent, Pattern: `(?i)fortiweb`},
			{Type: CheckTypeContent, Pattern: `(?i)fortinet`},
			{Type: CheckTypeContent, Pattern: `(?i).fgd_icon`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Wordfence
	{
		Name:        "Wordfence",
		Vendor:      "Defiant Inc.",
		Description: "Wordfence Web Application Firewall (WordPress)",
		Priority:    50,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)wordfence`},
			{Type: CheckTypeContent, Pattern: `(?i)generated\s*by\s*wordfence`},
			{Type: CheckTypeContent, Pattern: `(?i)your\s*access\s*to\s*this\s*site\s*has\s*been\s*limited`},
			{Type: CheckTypeCode, Pattern: `^(403|503)$`},
		},
	},

	// Fastly
	{
		Name:        "Fastly",
		Vendor:      "Fastly Inc.",
		Description: "Fastly CDN and WAF",
		Priority:    45,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-Fastly-Request-ID", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "Fastly-Debug-Path", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "Fastly-Debug-Digest", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)fastly`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Azure Front Door
	{
		Name:        "Azure Front Door",
		Vendor:      "Microsoft Azure",
		Description: "Azure Front Door WAF",
		Priority:    40,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-Azure-Ref", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-Azure-RequestChain", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-Cache", Pattern: `(?i)azure`},
			{Type: CheckTypeContent, Pattern: `(?i)azure`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Citrix NetScaler
	{
		Name:        "Citrix NetScaler",
		Vendor:      "Citrix Systems",
		Description: "Citrix NetScaler Application Firewall",
		Priority:    35,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Via", Pattern: `(?i)NS-CACHE`},
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)netscaler`},
			{Type: CheckTypeCookie, Pattern: `ns_af`},
			{Type: CheckTypeCookie, Pattern: `citrix_ns_id`},
			{Type: CheckTypeCookie, Pattern: `NSC_`},
			{Type: CheckTypeContent, Pattern: `(?i)netscaler`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// StackPath (formerly MaxCDN)
	{
		Name:        "StackPath",
		Vendor:      "StackPath LLC",
		Description: "StackPath WAF (formerly MaxCDN)",
		Priority:    30,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)stackpath`},
			{Type: CheckTypeContent, Pattern: `(?i)stackpath`},
			{Type: CheckTypeContent, Pattern: `(?i)you\s*don't\s*have\s*permission`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Radware AppWall
	{
		Name:        "Radware AppWall",
		Vendor:      "Radware Ltd.",
		Description: "Radware AppWall Web Application Firewall",
		Priority:    25,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-SL-CompState", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)radware`},
			{Type: CheckTypeContent, Pattern: `(?i)appwall`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// DenyAll
	{
		Name:        "DenyAll",
		Vendor:      "Rohde & Schwarz Cybersecurity",
		Description: "DenyAll Web Application Firewall",
		Priority:    20,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `sessioncookie`},
			{Type: CheckTypeContent, Pattern: `(?i)denyall`},
			{Type: CheckTypeContent, Pattern: `(?i)condition\s*intercepted`},
			{Type: CheckTypeCode, Pattern: `^(403|503)$`},
		},
	},

	// Wallarm
	{
		Name:        "Wallarm",
		Vendor:      "Wallarm Inc.",
		Description: "Wallarm Web Application Firewall",
		Priority:    15,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)wallarm`},
			{Type: CheckTypeContent, Pattern: `(?i)wallarm`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Reblaze
	{
		Name:        "Reblaze",
		Vendor:      "Reblaze Technologies",
		Description: "Reblaze Web Application Firewall",
		Priority:    10,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)reblaze`},
			{Type: CheckTypeCookie, Pattern: `rbzid`},
			{Type: CheckTypeContent, Pattern: `(?i)reblaze`},
			{Type: CheckTypeContent, Pattern: `(?i)access\s*denied.*?reblaze`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// PerimeterX
	{
		Name:        "PerimeterX",
		Vendor:      "PerimeterX Inc.",
		Description: "PerimeterX Bot Defender",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `_px\d?`},
			{Type: CheckTypeContent, Pattern: `(?i)perimeterx`},
			{Type: CheckTypeContent, Pattern: `(?i)access\s*denied.*?px`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},

	// Additional WAFs (simplified checks)
	{
		Name:        "Arbor Networks",
		Vendor:      "NETSCOUT Arbor",
		Description: "Arbor Networks Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)arbor\s*networks`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "BinarySec",
		Vendor:      "BinarySec",
		Description: "BinarySec Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-BinarySec-Via", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-BinarySec-NoCache", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)binarysec`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "BitNinja",
		Vendor:      "BitNinja.io",
		Description: "BitNinja Server Security",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)bitninja`},
			{Type: CheckTypeContent, Pattern: `(?i)security\s*check\s*by\s*bitninja`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "BlockDoS",
		Vendor:      "BlockDoS",
		Description: "BlockDoS Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)blockdos`},
			{Type: CheckTypeContent, Pattern: `(?i)blockdos`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "ChinaCache",
		Vendor:      "ChinaCache",
		Description: "ChinaCache CDN WAF",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Powered-By-ChinaCache", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)chinacache`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Comodo",
		Vendor:      "Comodo Inc.",
		Description: "Comodo Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)comodo`},
			{Type: CheckTypeContent, Pattern: `(?i)comodo.*?waf`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "DotDefender",
		Vendor:      "Applicure Technologies",
		Description: "DotDefender Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-dotDefender-denied", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)dotdefender`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "EdgeCast",
		Vendor:      "Verizon Digital Media Services",
		Description: "EdgeCast WAF",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)edgecast`},
			{Type: CheckTypeContent, Pattern: `(?i)edgecast`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Huawei Cloud WAF",
		Vendor:      "Huawei Technologies",
		Description: "Huawei Cloud Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)huawei.*?waf`},
			{Type: CheckTypeCode, Pattern: `^418$`},
		},
	},
	{
		Name:        "Incapsula",
		Vendor:      "Imperva Inc.",
		Description: "Imperva Incapsula (Legacy)",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `incap_ses`},
			{Type: CheckTypeContent, Pattern: `(?i)incapsula`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Jiasule",
		Vendor:      "Jiasule",
		Description: "Jiasule Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)jiasule`},
			{Type: CheckTypeCookie, Pattern: `__jsluid`},
			{Type: CheckTypeContent, Pattern: `(?i)jiasule`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "KeyCDN",
		Vendor:      "KeyCDN",
		Description: "KeyCDN WAF",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)keycdn`},
			{Type: CheckTypeContent, Pattern: `(?i)keycdn`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "NAXSI",
		Vendor:      "NBS System",
		Description: "NAXSI Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)naxsi`},
			{Type: CheckTypeContent, Pattern: `(?i)blocked\s*by\s*naxsi`},
			{Type: CheckTypeCode, Pattern: `^(403|500)$`},
		},
	},
	{
		Name:        "NSFocus",
		Vendor:      "NSFocus Inc.",
		Description: "NSFocus Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)nsfocus`},
			{Type: CheckTypeContent, Pattern: `(?i)nsfocus`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Palo Alto",
		Vendor:      "Palo Alto Networks",
		Description: "Palo Alto Next-Generation Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)palo\s*alto`},
			{Type: CheckTypeContent, Pattern: `(?i)access\s*denied.*?firewall`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Safe3",
		Vendor:      "Safe3",
		Description: "Safe3 Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-Powered-By", Pattern: `(?i)safe3`},
			{Type: CheckTypeContent, Pattern: `(?i)safe3`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "SafeDog",
		Vendor:      "SafeDog",
		Description: "SafeDog Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)safedog`},
			{Type: CheckTypeCookie, Pattern: `safedog`},
			{Type: CheckTypeContent, Pattern: `(?i)safedog`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "SiteGuard",
		Vendor:      "Sakura Inc.",
		Description: "SiteGuard Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)siteguard`},
			{Type: CheckTypeContent, Pattern: `(?i)siteguard`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "SonicWall",
		Vendor:      "SonicWall Inc.",
		Description: "SonicWall Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)sonicwall`},
			{Type: CheckTypeContent, Pattern: `(?i)sonicwall`},
			{Type: CheckTypeContent, Pattern: `(?i)this\s*request\s*is\s*blocked`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Sophos",
		Vendor:      "Sophos Ltd.",
		Description: "Sophos UTM Web Protection",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)sophos`},
			{Type: CheckTypeContent, Pattern: `(?i)blocked\s*by\s*sophos`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Squarespace",
		Vendor:      "Squarespace Inc.",
		Description: "Squarespace Web Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)squarespace`},
			{Type: CheckTypeContent, Pattern: `(?i)firewall.*?squarespace`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Stingray",
		Vendor:      "Pulse Secure",
		Description: "Stingray Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-Mapping", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)stingray`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Tencent Cloud WAF",
		Vendor:      "Tencent Cloud",
		Description: "Tencent Cloud Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)tencent`},
			{Type: CheckTypeContent, Pattern: `(?i)tencent.*?waf`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Varnish",
		Vendor:      "Varnish Software",
		Description: "Varnish Cache with WAF",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Via", Pattern: `(?i)varnish`},
			{Type: CheckTypeHeader, Key: "X-Varnish", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)varnish`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "WebKnight",
		Vendor:      "AQTRONIX",
		Description: "WebKnight Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)webknight`},
			{Type: CheckTypeContent, Pattern: `(?i)webknight`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "West263CDN",
		Vendor:      "West263CDN",
		Description: "West263CDN Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-Cache", Pattern: `(?i)west263cdn`},
			{Type: CheckTypeContent, Pattern: `(?i)west263cdn`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Yundun",
		Vendor:      "Yundun",
		Description: "Yundun Web Application Firewall",
		Priority:    5,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)yundun`},
			{Type: CheckTypeCookie, Pattern: `yunsuo_session`},
			{Type: CheckTypeContent, Pattern: `(?i)yundun`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
}

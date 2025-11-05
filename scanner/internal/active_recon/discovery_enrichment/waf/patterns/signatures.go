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

	// European WAFs
	{
		Name:        "Airlock",
		Vendor:      "Phion/Ergon",
		Description: "Airlock Secure Access Hub (Swiss)",
		Priority:    75,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `^al[_-]?(sess|lb)=`},
			{Type: CheckTypeContent, Pattern: `(?i)server detected a syntax error in your request`},
			{Type: CheckTypeContent, Pattern: `(?i)airlock`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "TransIP Web Firewall",
		Vendor:      "TransIP",
		Description: "TransIP Web Application Firewall (Netherlands)",
		Priority:    35,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-TransIP-Backend", Pattern: `.+`},
			{Type: CheckTypeHeader, Key: "X-TransIP-Balancer", Pattern: `.+`},
			{Type: CheckTypeContent, Pattern: `(?i)transip`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "NinjaFirewall",
		Vendor:      "NinTechNet",
		Description: "NinjaFirewall Web Application Firewall (French)",
		Priority:    40,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)<title>NinjaFirewall.{0,10}?\d{3}.forbidden`},
			{Type: CheckTypeContent, Pattern: `(?i)For security reasons.{0,10}?it was blocked and logged`},
			{Type: CheckTypeContent, Pattern: `(?i)ninjafirewall`},
			{Type: CheckTypeCode, Pattern: `^(403|503)$`},
		},
	},
	{
		Name:        "WebARX",
		Vendor:      "WebARX Security Solutions",
		Description: "WebARX Web Application Firewall (European)",
		Priority:    30,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)WebARX.{0,10}?Web Application Firewall`},
			{Type: CheckTypeContent, Pattern: `(?i)www\.webarxsecurity\.com`},
			{Type: CheckTypeContent, Pattern: `/wp-content/plugins/webarx/includes/`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "NevisProxy",
		Vendor:      "AdNovum",
		Description: "NevisProxy Security Gateway (Swiss)",
		Priority:    60,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `^Navajo`},
			{Type: CheckTypeCookie, Pattern: `^NP_ID`},
			{Type: CheckTypeContent, Pattern: `(?i)nevis`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "WatchGuard",
		Vendor:      "WatchGuard Technologies",
		Description: "WatchGuard Web Application Firewall",
		Priority:    55,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)WatchGuard`},
			{Type: CheckTypeContent, Pattern: `(?i)Request denied by WatchGuard Firewall`},
			{Type: CheckTypeContent, Pattern: `(?i)WatchGuard Technologies Inc\.`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "IBM WebSEAL",
		Vendor:      "IBM",
		Description: "IBM WebSEAL Application Gateway",
		Priority:    70,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)WebSEAL`},
			{Type: CheckTypeContent, Pattern: `(?i)This is a WebSEAL error message template file`},
			{Type: CheckTypeContent, Pattern: `(?i)WebSEAL server received an invalid HTTP request`},
			{Type: CheckTypeContent, Pattern: `(?i)webseal`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "ZScaler",
		Vendor:      "Accenture",
		Description: "ZScaler Cloud Security Platform",
		Priority:    80,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)ZScaler`},
			{Type: CheckTypeContent, Pattern: `(?i)Access Denied.{0,10}?Accenture Policy`},
			{Type: CheckTypeContent, Pattern: `(?i)policies\.accenture\.com`},
			{Type: CheckTypeContent, Pattern: `(?i)login\.zscloud\.net/img_logo_new1\.png`},
			{Type: CheckTypeContent, Pattern: `(?i)Zscaler to protect you from internet threats`},
			{Type: CheckTypeContent, Pattern: `(?i)Internet Security by ZScaler`},
			{Type: CheckTypeContent, Pattern: `(?i)Accenture.{0,10}?webfilters indicate that the site likely contains`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "IBM DataPower",
		Vendor:      "IBM",
		Description: "IBM DataPower Gateway",
		Priority:    65,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "X-Backside-Transport", Pattern: `(OK|FAIL)`},
			{Type: CheckTypeContent, Pattern: `(?i)datapower`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Qrator",
		Vendor:      "Qrator Labs",
		Description: "Qrator DDoS Protection (Russian/EU)",
		Priority:    45,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)QRATOR`},
			{Type: CheckTypeContent, Pattern: `(?i)qrator`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "PT Application Firewall",
		Vendor:      "Positive Technologies",
		Description: "Positive Technologies Application Firewall (Russian)",
		Priority:    50,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)<h1.{0,10}?Forbidden`},
			{Type: CheckTypeContent, Pattern: `(?i)<pre>Request.ID:.{0,10}?\d{4}-(\d{2})+.{0,35}?pre>`},
			{Type: CheckTypeContent, Pattern: `(?i)positive technologies`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "HyperGuard",
		Vendor:      "Art of Defense",
		Description: "HyperGuard Web Application Firewall (Russian/EU)",
		Priority:    40,
		Checks: []Check{
			{Type: CheckTypeCookie, Pattern: `^WODSESSION=`},
			{Type: CheckTypeContent, Pattern: `(?i)hyperguard`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "GreyWizard",
		Vendor:      "Grey Wizard",
		Description: "GreyWizard Web Security (European)",
		Priority:    30,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)greywizard`},
			{Type: CheckTypeContent, Pattern: `(?i)<(title|h\d{1})>Grey Wizard`},
			{Type: CheckTypeContent, Pattern: `(?i)contact the website owner or Grey Wizard`},
			{Type: CheckTypeContent, Pattern: `(?i)We.ve detected attempted attack or non standard traffic from your ip address`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Google Cloud Armor",
		Vendor:      "Google Cloud",
		Description: "Google Cloud Armor DDoS Protection",
		Priority:    85,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Via", Pattern: `(?i)1\.1 google`},
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)ghs`},
			{Type: CheckTypeContent, Pattern: `(?i)google cloud armor`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "LiteSpeed",
		Vendor:      "LiteSpeed Technologies",
		Description: "LiteSpeed Web Application Firewall",
		Priority:    40,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)LiteSpeed`},
			{Type: CheckTypeContent, Pattern: `(?i)Proudly powered by litespeed web server`},
			{Type: CheckTypeContent, Pattern: `(?i)www\.litespeedtech\.com/error-page`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Shield Security",
		Vendor:      "One Dollar Plugin",
		Description: "Shield Security WordPress Plugin",
		Priority:    25,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)You were blocked by the Shield`},
			{Type: CheckTypeContent, Pattern: `(?i)remaining transgression\(s\) against this site`},
			{Type: CheckTypeContent, Pattern: `(?i)Something in the URL.{0,5}?Form or Cookie data wasn't appropriate`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Microsoft URLScan",
		Vendor:      "Microsoft",
		Description: "Microsoft URLScan Security Filter",
		Priority:    35,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)Rejected[-_]By[_-]UrlScan`},
			{Type: CheckTypeContent, Pattern: `(?i)A custom filter or module.{0,4}?such as URLScan`},
			{Type: CheckTypeCode, Pattern: `^(403|404)$`},
		},
	},
	{
		Name:        "Microsoft RequestValidationMode",
		Vendor:      "Microsoft",
		Description: "ASP.NET Request Validation",
		Priority:    30,
		Checks: []Check{
			{Type: CheckTypeContent, Pattern: `(?i)Request Validation has detected a potentially dangerous client input`},
			{Type: CheckTypeContent, Pattern: `(?i)ASP\.NET has detected data in the request`},
			{Type: CheckTypeContent, Pattern: `(?i)HttpRequestValidationException`},
			{Type: CheckTypeCode, Pattern: `^(400|500)$`},
		},
	},
	{
		Name:        "Mission Control Shield",
		Vendor:      "Mission Control",
		Description: "Mission Control Application Shield (UK)",
		Priority:    45,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)Mission Control Application Shield`},
			{Type: CheckTypeContent, Pattern: `(?i)mission control`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Profense",
		Vendor:      "ArmorLogic",
		Description: "Profense Web Application Firewall",
		Priority:    40,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)Profense`},
			{Type: CheckTypeCookie, Pattern: `^PLBSID=`},
			{Type: CheckTypeContent, Pattern: `(?i)profense`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
	{
		Name:        "Link11 WAAP",
		Vendor:      "Link11",
		Description: "Link11 Web Application and API Protection (German)",
		Priority:    50,
		Checks: []Check{
			{Type: CheckTypeHeader, Key: "Server", Pattern: `(?i)rhino-core-shield`},
			{Type: CheckTypeContent, Pattern: `(?i)link11`},
			{Type: CheckTypeCode, Pattern: `^403$`},
		},
	},
}

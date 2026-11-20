package shared

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

// BlockedBodyPrefix is how much of a response body BlockedResponse needs to see to recognize
// a WAF challenge page.
const BlockedBodyPrefix = 64 << 10

// challengeMarkers are body fragments that only a WAF block or challenge page carries. They are
// matched case-insensitively. Fragments that also appear on normal pages behind the same WAF
// (Cloudflare's /cdn-cgi/challenge-platform/ bot script, Imperva's /_Incapsula_Resource
// script) are not listed.
var challengeMarkers = []string{
	"<title>just a moment...</title>",                 // Cloudflare managed challenge
	"<title>attention required! | cloudflare</title>", // Cloudflare block
	"window._cf_chl_opt",                              // Cloudflare challenge script
	"incapsula incident id",                           // Imperva Incapsula block
	"sucuri website firewall - access denied",         // Sucuri
	"errors.edgesuite.net",                            // Akamai "Access Denied ... Reference #"
	"<title>ddos-guard</title>",                       // DDoS-Guard
}

// BlockedResponse returns an error when a response may come from a block, a challenge or an
// outage rather than the application: HTTP 403, 429 or 5xx, a WAF challenge header
// (cf-mitigated, x-amzn-waf-action) or a known WAF challenge page in body (the first
// BlockedBodyPrefix bytes; nil when the caller did not read it). A check of such a response is
// incomplete: what it did not find may only be hidden.
func BlockedResponse(url string, status int, header http.Header, body []byte) error {
	if status == http.StatusForbidden || status == http.StatusTooManyRequests || status >= 500 {
		return fmt.Errorf("%s answered HTTP %d: the response may not be the application's", url, status)
	}
	if v := header.Get("Cf-Mitigated"); v != "" {
		return fmt.Errorf("%s answered with a Cloudflare challenge (cf-mitigated: %s)", url, v)
	}
	if v := header.Get("X-Amzn-Waf-Action"); v != "" {
		return fmt.Errorf("%s answered with an AWS WAF action (%s)", url, v)
	}
	if len(body) > BlockedBodyPrefix {
		body = body[:BlockedBodyPrefix]
	}
	lower := bytes.ToLower(body)
	for _, m := range challengeMarkers {
		if bytes.Contains(lower, []byte(m)) {
			return fmt.Errorf("%s answered with a WAF challenge page (%q)", url, strings.TrimSpace(m))
		}
	}
	return nil
}

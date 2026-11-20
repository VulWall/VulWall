package shared

import (
	"net/http"
	"testing"
)

func TestBlockedResponse(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		header  http.Header
		body    string
		blocked bool
	}{
		{"plain 200", 200, http.Header{}, "<html><title>Shop</title></html>", false},
		{"404 is an answer", 404, http.Header{}, "not found", false},
		{"401 is an answer", 401, http.Header{}, "", false},
		{"403", 403, http.Header{}, "", true},
		{"429", 429, http.Header{}, "", true},
		{"500", 500, http.Header{}, "", true},
		{"503", 503, http.Header{}, "", true},
		{"cf-mitigated header", 200, http.Header{"Cf-Mitigated": {"challenge"}}, "", true},
		{"aws waf header", 202, http.Header{"X-Amzn-Waf-Action": {"challenge"}}, "", true},
		{"cloudflare challenge page", 200, http.Header{}, "<!DOCTYPE html><html><head><title>Just a moment...</title>", true},
		{"cloudflare block page", 200, http.Header{}, "<title>Attention Required! | Cloudflare</title>", true},
		{"cloudflare challenge script", 200, http.Header{}, "<script>window._cf_chl_opt={cvId:'3'}</script>", true},
		{"akamai access denied", 200, http.Header{}, `<H1>Access Denied</H1> Reference&#32;&#35;18.1 https&#58;&#47;&#47;errors&#46;edgesuite&#46;net errors.edgesuite.net`, true},
		{"incapsula block", 200, http.Header{}, `Request unsuccessful. Incapsula incident ID: 123-456`, true},
		{"incapsula script on a normal page", 200, http.Header{}, `<script src="/_Incapsula_Resource?SWJIYLWA=719d34d3"></script>`, false},
		{"sucuri", 200, http.Header{}, "<title>Sucuri WebSite Firewall - Access Denied</title>", true},
		{"cloudflare bot script on a normal page", 200, http.Header{}, `<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>`, false},
	}
	for _, c := range cases {
		err := BlockedResponse("https://x", c.status, c.header, []byte(c.body))
		if (err != nil) != c.blocked {
			t.Errorf("%s: blocked = %v (%v), want %v", c.name, err != nil, err, c.blocked)
		}
	}
}

func TestBlockedResponseLooksOnlyAtThePrefix(t *testing.T) {
	body := make([]byte, BlockedBodyPrefix+100)
	for i := range body {
		body[i] = 'a'
	}
	copy(body[BlockedBodyPrefix+10:], "<title>Just a moment...</title>")
	if err := BlockedResponse("https://x", 200, http.Header{}, body); err != nil {
		t.Fatalf("marker past the prefix: %v, want nil", err)
	}
}

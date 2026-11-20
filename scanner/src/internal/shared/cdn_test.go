package shared

import "testing"

func TestCDNProvider(t *testing.T) {
	cases := map[string]string{
		"104.20.23.154":        "Cloudflare", // example.com
		"172.66.147.243":       "Cloudflare",
		"2606:4700::1":         "Cloudflare",
		"151.101.65.140":       "Fastly",
		"13.32.0.1":            "CloudFront",
		"3.80.0.1":             "", // EC2, not CloudFront
		"8.8.8.8":              "",
		"203.0.113.10":         "",
		"::ffff:104.20.23.154": "Cloudflare",
		"not-an-ip":            "",
		"":                     "",
	}
	for ip, want := range cases {
		if got := CDNProvider(ip); got != want {
			t.Errorf("CDNProvider(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestCDNRangesLoaded(t *testing.T) {
	seen := map[string]int{}
	for _, r := range cdnRanges {
		seen[r.provider]++
	}
	for _, p := range []string{"Cloudflare", "Fastly", "CloudFront", "AzureFrontDoor"} {
		if seen[p] == 0 {
			t.Errorf("no %s ranges in cdn_ranges.txt", p)
		}
	}
}

package shared

import (
	_ "embed"
	"fmt"
	"net/netip"
	"strings"
)

// cdnRangesFile lists the shared edge ranges of the CDNs that publish them (Cloudflare,
// Fastly, CloudFront, Azure Front Door), one "<provider> <cidr>" per line. It is a snapshot
// embedded in the binary, so a lookup needs no network and no enrichment result; regenerate
// it with scripts/update-cdn-ranges.sh. Akamai and Google publish no edge-only list and are
// not in it.
//
//go:embed cdn_ranges.txt
var cdnRangesFile string

// DiscoveryMetaCDNEdge is the discoveries.metadata key on an IP discovery whose address is a
// CDN edge: the CDN's name (CDNProvider). Port ingestion keeps it current; the web app shows
// that such an address gets no nuclei scan by IP (only its names are scanned).
const DiscoveryMetaCDNEdge = "cdn_edge"

type cdnRange struct {
	provider string
	prefix   netip.Prefix
}

var cdnRanges = mustParseCDNRanges(cdnRangesFile)

func mustParseCDNRanges(data string) []cdnRange {
	var ranges []cdnRange
	for n, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		provider, cidr, ok := strings.Cut(line, " ")
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if !ok || err != nil {
			panic(fmt.Sprintf("cdn_ranges.txt line %d: %q", n+1, line))
		}
		ranges = append(ranges, cdnRange{provider: provider, prefix: prefix.Masked()})
	}
	return ranges
}

// CDNProvider returns the CDN whose shared edge range contains ip, or "" when ip is in none
// of them (or is not an IP). Such an address serves many customers' sites and answers only
// requests that name a site: a scan of it by IP tests the CDN, not the customer.
func CDNProvider(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	for _, r := range cdnRanges {
		if r.prefix.Contains(addr) {
			return r.provider
		}
	}
	return ""
}

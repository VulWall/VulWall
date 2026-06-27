package subfinderx

import (
	"context"
	"io"
	"sort"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"go.uber.org/zap"
)

// Client wraps the subfinder runner for passive subdomain enumeration.
// Zero API keys — uses free passive sources only (crt.sh, HackerTarget, DNSDumpster, RapidDNS, etc.).
type Client struct {
	runner *runner.Runner
	logger *zap.Logger
}

// NewClient creates a subfinder client reused across jobs (ConsumerBatchSize=1 → serial).
// ponytail: 2-min enumeration cap hardcoded; promote to SUBFINDER_MAX_TIME_MINS env if scans need tuning.
func NewClient(logger *zap.Logger) (*Client, error) {
	opts := &runner.Options{
		Threads:            10,
		Timeout:            30, // per-source timeout in seconds
		MaxEnumerationTime: 2,  // total cap in minutes
	}
	r, err := runner.NewRunner(opts)
	if err != nil {
		return nil, err
	}
	return &Client{runner: r, logger: logger}, nil
}

// DiscoverSubdomains discovers passive subdomains for domain.
// Returns sorted FQDNs, excluding the apex domain itself and wildcards.
func (c *Client) DiscoverSubdomains(ctx context.Context, domain string) ([]string, error) {
	sourceMap, err := c.runner.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{io.Discard})
	if err != nil {
		return nil, err
	}

	var results []string
	for sub := range sourceMap {
		sub = strings.TrimSpace(strings.ToLower(sub))
		if sub == "" || sub == domain || strings.Contains(sub, "*") {
			continue
		}
		results = append(results, sub)
	}
	sort.Strings(results)

	c.logger.Info("subfinder enumeration complete",
		zap.String("domain", domain),
		zap.Int("subdomains_found", len(results)),
	)
	return results, nil
}

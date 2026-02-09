package cloud

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment/cloud/parsers"
	"go.uber.org/zap"
)

// CloudInfo contains cloud provider information for an IP
type CloudInfo struct {
	Provider string // "AWS", "Azure", "GCP", "Fastly"
	Region   string // "us-east-1", "westus", "asia-northeast1", "global"
	Service  string // "EC2", "S3", "COMPUTE", "STORAGE", "CDN" (may be empty)
}

// cidrEntry wraps an IP range with its metadata for CIDR ranger
type cidrEntry struct {
	network  net.IPNet
	provider string
	region   string
	service  string
}

// Network returns the network for cidranger interface
func (e *cidrEntry) Network() net.IPNet {
	return e.network
}

// Cache provides fast IP-to-cloud-provider lookups using a CIDR tree
type Cache struct {
	ranger     cidranger.Ranger
	ranges     []parsers.IPRange
	lastUpdate time.Time
	stats      CacheStats
	mu         sync.RWMutex
	logger     *zap.Logger
}

// CacheStats contains cache statistics
type CacheStats struct {
	TotalRanges    int
	AWSRanges      int
	AzureRanges    int
	GCPRanges      int
	FastlyRanges   int
	IPv4Ranges     int
	IPv6Ranges     int
	LastUpdateTime time.Time
}

// NewCache creates a new CIDR cache
func NewCache(logger *zap.Logger) *Cache {
	return &Cache{
		ranger: cidranger.NewPCTrieRanger(),
		logger: logger,
	}
}

// Build builds the CIDR tree from IP ranges
func (c *Cache) Build(ranges []parsers.IPRange) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Reset ranger
	c.ranger = cidranger.NewPCTrieRanger()
	c.ranges = ranges
	c.stats = CacheStats{
		LastUpdateTime: time.Now(),
	}

	// Insert each range into the CIDR tree
	for _, ipRange := range ranges {
		// Parse CIDR
		_, network, err := net.ParseCIDR(ipRange.CIDR)
		if err != nil {
			c.logger.Warn("Failed to parse CIDR, skipping",
				zap.String("cidr", ipRange.CIDR),
				zap.String("provider", ipRange.Provider),
				zap.Error(err),
			)
			continue
		}

		// Create entry
		entry := &cidrEntry{
			network:  *network,
			provider: ipRange.Provider,
			region:   ipRange.Region,
			service:  ipRange.Service,
		}

		// Insert into ranger
		if err := c.ranger.Insert(entry); err != nil {
			c.logger.Warn("Failed to insert CIDR into ranger",
				zap.String("cidr", ipRange.CIDR),
				zap.String("provider", ipRange.Provider),
				zap.Error(err),
			)
			continue
		}

		// Update stats
		c.stats.TotalRanges++
		switch ipRange.Provider {
		case "AWS":
			c.stats.AWSRanges++
		case "Azure":
			c.stats.AzureRanges++
		case "GCP":
			c.stats.GCPRanges++
		case "Fastly":
			c.stats.FastlyRanges++
		}

		// Count IPv4 vs IPv6
		if network.IP.To4() != nil {
			c.stats.IPv4Ranges++
		} else {
			c.stats.IPv6Ranges++
		}
	}

	c.lastUpdate = time.Now()

	c.logger.Info("CIDR cache built successfully",
		zap.Int("total_ranges", c.stats.TotalRanges),
		zap.Int("aws_ranges", c.stats.AWSRanges),
		zap.Int("azure_ranges", c.stats.AzureRanges),
		zap.Int("gcp_ranges", c.stats.GCPRanges),
		zap.Int("fastly_ranges", c.stats.FastlyRanges),
		zap.Int("ipv4_ranges", c.stats.IPv4Ranges),
		zap.Int("ipv6_ranges", c.stats.IPv6Ranges),
	)

	return nil
}

// Lookup performs IP lookup in the CIDR tree
func (c *Cache) Lookup(ipStr string) (*CloudInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Lookup in ranger
	entries, err := c.ranger.ContainingNetworks(ip)
	if err != nil {
		return nil, fmt.Errorf("ranger lookup failed: %w", err)
	}

	// No match found
	if len(entries) == 0 {
		return nil, nil
	}

	// Return first match (most specific CIDR due to ranger implementation)
	if entry, ok := entries[0].(*cidrEntry); ok {
		return &CloudInfo{
			Provider: entry.provider,
			Region:   entry.region,
			Service:  entry.service,
		}, nil
	}

	return nil, fmt.Errorf("unexpected entry type in ranger")
}

// GetStats returns cache statistics
func (c *Cache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// GetLastUpdate returns the last update time
func (c *Cache) GetLastUpdate() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastUpdate
}

// Size returns the number of ranges in the cache
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats.TotalRanges
}

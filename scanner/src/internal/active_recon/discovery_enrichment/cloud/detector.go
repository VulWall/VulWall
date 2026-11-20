package cloud

import (
	"context"
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/discovery_enrichment/cloud/parsers"
	"go.uber.org/zap"
)

// Detector is the main cloud provider detector
type Detector struct {
	sources    []CloudSource
	downloader *Downloader
	cache      *Cache
	logger     *zap.Logger
}

// NewDetector creates a new cloud detector
func NewDetector(dataDir string, logger *zap.Logger) (*Detector, error) {
	// Get default cloud sources
	sources := GetDefaultCloudSources()

	// Create downloader
	downloader := NewDownloader(dataDir, logger)

	// Create cache
	cache := NewCache(logger)

	detector := &Detector{
		sources:    sources,
		downloader: downloader,
		cache:      cache,
		logger:     logger,
	}

	// Initialize detector (download and build cache)
	if err := detector.Initialize(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize detector: %w", err)
	}

	return detector, nil
}

// Initialize downloads IP ranges and builds the cache
func (d *Detector) Initialize(ctx context.Context) error {
	d.logger.Info("Initializing cloud detector")

	// Download IP ranges for all enabled sources
	if err := d.downloader.DownloadAll(ctx, d.sources); err != nil {
		// Try to fall back to cached files
		d.logger.Warn("Failed to download IP ranges, attempting to use cached files",
			zap.Error(err),
		)
	}

	// Load and parse all sources
	var allRanges []parsers.IPRange
	for _, source := range d.sources {
		if !source.Enabled {
			continue
		}

		// Load file from disk
		data, err := d.downloader.LoadFromDisk(source)
		if err != nil {
			d.logger.Error("Failed to load source from disk",
				zap.String("provider", source.Name),
				zap.Error(err),
			)
			continue
		}

		// Parse IP ranges
		ranges, err := source.Parser.Parse(data)
		if err != nil {
			d.logger.Error("Failed to parse source",
				zap.String("provider", source.Name),
				zap.Error(err),
			)
			continue
		}

		d.logger.Info("Parsed cloud provider ranges",
			zap.String("provider", source.Name),
			zap.Int("ranges", len(ranges)),
		)

		allRanges = append(allRanges, ranges...)
	}

	// Check if we have any ranges
	if len(allRanges) == 0 {
		return fmt.Errorf("no IP ranges loaded from any cloud provider")
	}

	// Build cache
	if err := d.cache.Build(allRanges); err != nil {
		return fmt.Errorf("failed to build cache: %w", err)
	}

	// Log stats
	stats := d.cache.GetStats()
	d.logger.Info("Cloud detector initialized successfully",
		zap.Int("total_ranges", stats.TotalRanges),
		zap.Int("aws_ranges", stats.AWSRanges),
		zap.Int("azure_ranges", stats.AzureRanges),
		zap.Int("gcp_ranges", stats.GCPRanges),
		zap.Int("fastly_ranges", stats.FastlyRanges),
		zap.Int("ipv4_ranges", stats.IPv4Ranges),
		zap.Int("ipv6_ranges", stats.IPv6Ranges),
	)

	return nil
}

// Detect performs cloud provider detection for an IP address
func (d *Detector) Detect(ipStr string) (*CloudInfo, error) {
	return d.cache.Lookup(ipStr)
}

// GetStats returns cache statistics
func (d *Detector) GetStats() CacheStats {
	return d.cache.GetStats()
}

// Refresh re-downloads IP ranges and rebuilds the cache
// This can be called periodically to keep the cache up-to-date
func (d *Detector) Refresh(ctx context.Context) error {
	d.logger.Info("Refreshing cloud detector cache")

	// Download IP ranges
	if err := d.downloader.DownloadAll(ctx, d.sources); err != nil {
		return fmt.Errorf("failed to download IP ranges: %w", err)
	}

	// Re-initialize cache
	var allRanges []parsers.IPRange
	for _, source := range d.sources {
		if !source.Enabled {
			continue
		}

		// Load file from disk
		data, err := d.downloader.LoadFromDisk(source)
		if err != nil {
			d.logger.Error("Failed to load source from disk",
				zap.String("provider", source.Name),
				zap.Error(err),
			)
			continue
		}

		// Parse IP ranges
		ranges, err := source.Parser.Parse(data)
		if err != nil {
			d.logger.Error("Failed to parse source",
				zap.String("provider", source.Name),
				zap.Error(err),
			)
			continue
		}

		allRanges = append(allRanges, ranges...)
	}

	// Build cache
	if err := d.cache.Build(allRanges); err != nil {
		return fmt.Errorf("failed to build cache: %w", err)
	}

	d.logger.Info("Cloud detector cache refreshed successfully",
		zap.Int("total_ranges", len(allRanges)),
	)

	return nil
}

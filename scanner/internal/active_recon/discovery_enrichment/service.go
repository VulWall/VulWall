package discovery_enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment/geolocation"
	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment/waf/patterns"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Service orchestrates discovery enrichment (WAF detection + IP geolocation)
type Service struct {
	redis        *redis.Client
	wafDetector  *patterns.Detector
	geoEnricher  *geolocation.IPEnricher
	logger       *zap.Logger
}

// NewService creates a new discovery enrichment service
func NewService(redisClient *redis.Client, cfg *config.Config, logger *zap.Logger) (*Service, error) {
	// Initialize WAF detector
	wafDetector, err := patterns.NewDetector(logger, cfg.WAFRulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF detector: %w", err)
	}

	logger.Info("WAF detector initialized",
		zap.String("rules_path", cfg.WAFRulesPath),
	)

	// Initialize IP geolocation enricher (graceful failure if DB missing)
	var geoEnricher *geolocation.IPEnricher
	if cfg.IPEnrichmentDBPath != "" {
		geoEnricher, err = geolocation.NewIPEnricher(cfg.IPEnrichmentDBPath)
		if err != nil {
			logger.Warn("Failed to initialize IP enricher, continuing without geolocation",
				zap.String("db_path", cfg.IPEnrichmentDBPath),
				zap.Error(err))
		} else {
			logger.Info("IP geolocation enricher initialized",
				zap.String("db_path", cfg.IPEnrichmentDBPath))
		}
	}

	return &Service{
		redis:       redisClient,
		wafDetector: wafDetector,
		geoEnricher: geoEnricher,
		logger:      logger,
	}, nil
}

// ProcessEnrichment processes an enrichment job
func (s *Service) ProcessEnrichment(ctx context.Context, job shared.EnrichmentJob) error {
	s.logger.Info("Processing enrichment job",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("asset_type", job.AssetType),
		zap.String("discovery_id", job.DiscoveryID),
	)

	// Enrich based on asset type
	switch job.AssetType {
	case shared.AssetTypeDomain, shared.AssetTypeSubdomain:
		// For domains/subdomains: IP geolocation + WAF detection
		if job.IP != "" {
			s.enrichGeolocation(ctx, job)
		}
		if job.Host != "" {
			s.enrichWAF(ctx, job)
		}

	case shared.AssetTypeIP:
		// For IPs: IP geolocation only
		if job.IP != "" {
			s.enrichGeolocation(ctx, job)
		}

	default:
		s.logger.Warn("Unknown asset type, skipping enrichment",
			zap.String("asset_type", job.AssetType),
			zap.String("discovery_id", job.DiscoveryID),
		)
	}

	return nil
}

// enrichGeolocation performs IP geolocation enrichment
func (s *Service) enrichGeolocation(ctx context.Context, job shared.EnrichmentJob) {
	if s.geoEnricher == nil {
		s.logger.Debug("IP enricher not initialized, skipping geolocation",
			zap.String("discovery_id", job.DiscoveryID),
		)
		return
	}

	ipInfo, err := s.geoEnricher.Enrich(job.IP)
	if err != nil {
		s.logger.Debug("Failed to enrich IP with geolocation",
			zap.String("ip", job.IP),
			zap.Error(err),
		)
		return
	}

	s.logger.Debug("IP enriched with geolocation",
		zap.String("ip", job.IP),
		zap.String("continent", ipInfo.Continent),
		zap.String("country", ipInfo.Country),
		zap.String("isp", ipInfo.ISP),
	)

	// Publish geolocation enrichment
	enrichment := shared.EnrichmentFinding{
		TraceID:        job.TraceID,
		ScanID:         job.ScanID,
		OrgID:          job.OrgID,
		Source:         "discovery_enrichment",
		DiscoveryID:    job.DiscoveryID,
		EnrichmentType: "geolocation",
		Data: map[string]interface{}{
			"continent": ipInfo.Continent,
			"country":   ipInfo.Country,
			"isp":       ipInfo.ISP,
		},
		Timestamp: time.Now(),
	}

	if err := s.publishEnrichment(ctx, enrichment); err != nil {
		s.logger.Error("Failed to publish geolocation enrichment",
			zap.String("discovery_id", job.DiscoveryID),
			zap.Error(err),
		)
	}
}

// enrichWAF performs WAF detection enrichment
func (s *Service) enrichWAF(ctx context.Context, job shared.EnrichmentJob) {
	// Skip if no host
	if job.Host == "" {
		s.logger.Debug("No host for WAF detection",
			zap.String("discovery_id", job.DiscoveryID),
		)
		return
	}

	// Build target URL (try HTTPS first)
	targetURL := fmt.Sprintf("https://%s", job.Host)

	// Perform WAF detection
	wafName, err := s.wafDetector.Detect(ctx, targetURL)
	if err != nil {
		s.logger.Debug("WAF detection failed",
			zap.String("host", job.Host),
			zap.Error(err),
		)
		// Don't return error - just log and continue
		return
	}

	// Only publish enrichment if WAF was detected
	if wafName != "" {
		s.logger.Info("WAF detected, publishing enrichment",
			zap.String("trace_id", job.TraceID),
			zap.String("host", job.Host),
			zap.String("waf", wafName),
		)

		enrichment := shared.EnrichmentFinding{
			TraceID:        job.TraceID,
			ScanID:         job.ScanID,
			OrgID:          job.OrgID,
			Source:         "discovery_enrichment",
			DiscoveryID:    job.DiscoveryID,
			EnrichmentType: "waf",
			Data: map[string]interface{}{
				"waf_name": wafName,
			},
			Timestamp: time.Now(),
		}

		if err := s.publishEnrichment(ctx, enrichment); err != nil {
			s.logger.Error("Failed to publish WAF enrichment",
				zap.String("discovery_id", job.DiscoveryID),
				zap.Error(err),
			)
		}
	} else {
		s.logger.Debug("No WAF detected",
			zap.String("host", job.Host),
		)
	}
}

// publishEnrichment publishes enrichment data to Redis stream
func (s *Service) publishEnrichment(ctx context.Context, enrichment shared.EnrichmentFinding) error {
	// Marshal to JSON
	data, err := json.Marshal(enrichment)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment: %w", err)
	}

	// Publish to discovery_enrichment_results stream
	_, err = s.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: shared.StreamDiscoveryEnrichmentResults,
		Values: map[string]interface{}{
			"data": string(data),
		},
	}).Result()

	if err != nil {
		return fmt.Errorf("failed to publish to stream: %w", err)
	}

	s.logger.Info("Published enrichment",
		zap.String("trace_id", enrichment.TraceID),
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("enrichment_type", enrichment.EnrichmentType),
	)

	return nil
}

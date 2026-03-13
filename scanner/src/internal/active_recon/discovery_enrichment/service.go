package discovery_enrichment

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment/cloud"
	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment/geolocation"
	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment/waf/patterns"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service orchestrates discovery enrichment (WAF detection + IP geolocation + cloud detection)
type Service struct {
	redis         *redis.Client
	wafDetector   *patterns.Detector
	geoEnricher   *geolocation.IPEnricher
	cloudDetector *cloud.Detector
	logger        *zap.Logger
	tracer        trace.Tracer
}

// NewService creates a new discovery enrichment service
func NewService(redisClient *redis.Client, logger *zap.Logger) (*Service, error) {
	// Load service-specific settings via GetEnv
	wafRulesPath := config.GetEnv(config.EnvWAFRulesPath, "./internal/active_recon/discovery_enrichment/waf/patterns/waf_rules.json")
	ipEnrichmentDBPath := config.GetEnv(config.EnvIPEnrichmentDBPath, "./data/dbip-isp-country.mmdb")
	cloudDetectorEnabled := config.GetEnvBool(config.EnvCloudDetectorEnabled, true)
	cloudDataDir := config.GetEnv(config.EnvCloudDataDir, "./internal/active_recon/discovery_enrichment/cloud/data")

	// Initialize WAF detector
	wafDetector, err := patterns.NewDetector(logger, wafRulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF detector: %w", err)
	}

	logger.Info("WAF detector initialized",
		zap.String("rules_path", wafRulesPath),
	)

	// Initialize IP geolocation enricher (graceful failure if DB missing)
	var geoEnricher *geolocation.IPEnricher
	if ipEnrichmentDBPath != "" {
		geoEnricher, err = geolocation.NewIPEnricher(ipEnrichmentDBPath)
		if err != nil {
			logger.Warn("Failed to initialize IP enricher, continuing without geolocation",
				zap.String("db_path", ipEnrichmentDBPath),
				zap.Error(err))
		} else {
			logger.Info("IP geolocation enricher initialized",
				zap.String("db_path", ipEnrichmentDBPath))
		}
	}

	// Initialize cloud detector (graceful failure if disabled or errors)
	var cloudDetector *cloud.Detector
	if cloudDetectorEnabled {
		cloudDetector, err = cloud.NewDetector(cloudDataDir, logger)
		if err != nil {
			logger.Warn("Failed to initialize cloud detector, continuing without cloud detection",
				zap.String("data_dir", cloudDataDir),
				zap.Error(err))
		} else {
			logger.Info("Cloud detector initialized",
				zap.String("data_dir", cloudDataDir))
		}
	} else {
		logger.Info("Cloud detector disabled")
	}

	return &Service{
		redis:         redisClient,
		wafDetector:   wafDetector,
		geoEnricher:   geoEnricher,
		cloudDetector: cloudDetector,
		logger:        logger,
		tracer:        otel.Tracer("discovery-enrichment"),
	}, nil
}

// ProcessEnrichment processes an enrichment job
func (s *Service) ProcessEnrichment(ctx context.Context, job shared.EnrichmentJob) error {
	ctx, span := s.tracer.Start(ctx, "enrichment",
		trace.WithAttributes(
			attribute.String("org.id", job.OrgID),
			attribute.String("trace.id", job.TraceID),
			attribute.String("discovery.id", job.DiscoveryID),
			attribute.String("asset.type", job.AssetType),
		),
	)
	defer span.End()

	s.logger.Info("Processing enrichment job",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("asset_type", job.AssetType),
		zap.String("discovery_id", job.DiscoveryID),
	)

	// Enrich based on asset type
	switch job.AssetType {
	case shared.AssetTypeDomain, shared.AssetTypeSubdomain:
		// For domains/subdomains: IP geolocation + cloud detection + WAF detection
		if job.IP != "" {
			s.enrichGeolocation(ctx, job)
			s.enrichCloud(ctx, job)
		}
		if job.Host != "" {
			s.enrichWAF(ctx, job)
		}

	case shared.AssetTypeIP:
		// For IPs: IP geolocation + cloud detection
		if job.IP != "" {
			s.enrichGeolocation(ctx, job)
			s.enrichCloud(ctx, job)
		}

	default:
		s.logger.Warn("Unknown asset type, skipping enrichment",
			zap.String("asset_type", job.AssetType),
			zap.String("discovery_id", job.DiscoveryID),
		)
	}

	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

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
		Source:        "enrichment",
		DiscoveryID:    job.DiscoveryID,
		EnrichmentType: "geolocation",
		Data: map[string]interface{}{
			"continent": ipInfo.Continent,
			"country":   ipInfo.Country,
			"isp":       ipInfo.ISP,
		},
		Timestamp: time.Now(),
	}
	enrichment.TraceContext = telemetry.InjectTraceContext(ctx)

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
			Source:        "enrichment",
			DiscoveryID:    job.DiscoveryID,
			EnrichmentType: "waf",
			Data: map[string]interface{}{
				"waf_name": wafName,
			},
			Timestamp: time.Now(),
		}
		enrichment.TraceContext = telemetry.InjectTraceContext(ctx)

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

// enrichCloud performs cloud provider detection enrichment
func (s *Service) enrichCloud(ctx context.Context, job shared.EnrichmentJob) {
	if s.cloudDetector == nil {
		s.logger.Debug("Cloud detector not initialized, skipping cloud detection",
			zap.String("discovery_id", job.DiscoveryID),
		)
		return
	}

	cloudInfo, err := s.cloudDetector.Detect(job.IP)
	if err != nil {
		s.logger.Debug("Failed to detect cloud provider",
			zap.String("ip", job.IP),
			zap.Error(err),
		)
		return
	}

	// Only publish enrichment if cloud provider was detected
	if cloudInfo != nil {
		s.logger.Info("Cloud provider detected, publishing enrichment",
			zap.String("trace_id", job.TraceID),
			zap.String("ip", job.IP),
			zap.String("provider", cloudInfo.Provider),
			zap.String("region", cloudInfo.Region),
			zap.String("service", cloudInfo.Service),
		)

		enrichment := shared.EnrichmentFinding{
			TraceID:        job.TraceID,
			ScanID:         job.ScanID,
			OrgID:          job.OrgID,
			Source:        "enrichment",
			DiscoveryID:    job.DiscoveryID,
			EnrichmentType: "cloud",
			Data: map[string]interface{}{
				"provider": cloudInfo.Provider,
				"region":   cloudInfo.Region,
				"service":  cloudInfo.Service,
			},
			Timestamp: time.Now(),
		}
		enrichment.TraceContext = telemetry.InjectTraceContext(ctx)

		if err := s.publishEnrichment(ctx, enrichment); err != nil {
			s.logger.Error("Failed to publish cloud enrichment",
				zap.String("discovery_id", job.DiscoveryID),
				zap.Error(err),
			)
		}
	} else {
		s.logger.Debug("No cloud provider detected",
			zap.String("ip", job.IP),
		)
	}
}

// publishEnrichment publishes enrichment data to Redis stream
func (s *Service) publishEnrichment(ctx context.Context, enrichment shared.EnrichmentFinding) error {
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamDiscoveryEnrichmentResults, enrichment, 0); err != nil {
		return fmt.Errorf("failed to publish to stream: %w", err)
	}

	s.logger.Info("Published enrichment",
		zap.String("trace_id", enrichment.TraceID),
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("enrichment_type", enrichment.EnrichmentType),
	)

	return nil
}

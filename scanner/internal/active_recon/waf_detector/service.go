package waf_detector

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/active_recon/waf_detector/patterns"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Service orchestrates WAF detection
type Service struct {
	redis    *redis.Client
	detector *patterns.Detector
	logger   *zap.Logger
}

// NewService creates a new WAF detector service
func NewService(redisClient *redis.Client, logger *zap.Logger) (*Service, error) {
	detector, err := patterns.NewDetector(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create detector: %w", err)
	}

	return &Service{
		redis:    redisClient,
		detector: detector,
		logger:   logger,
	}, nil
}

// ProcessDiscovery processes a discovered asset and performs WAF detection
func (s *Service) ProcessDiscovery(ctx context.Context, target DetectionTarget) error {
	s.logger.Info("Processing discovery for WAF detection",
		zap.String("trace_id", target.TraceID),
		zap.String("org_id", target.OrgID),
		zap.String("target", target.TargetURL),
	)

	// Perform WAF detection
	wafName, err := s.detector.Detect(ctx, target.TargetURL)
	if err != nil {
		s.logger.Error("WAF detection failed",
			zap.String("trace_id", target.TraceID),
			zap.String("target", target.TargetURL),
			zap.Error(err),
		)
		// Don't return error - just log and continue
		// We don't want detection failures to block the pipeline
		return nil
	}

	// Only publish enrichment if WAF was detected
	if wafName != "" {
		s.logger.Info("WAF detected, publishing enrichment",
			zap.String("trace_id", target.TraceID),
			zap.String("waf", wafName),
		)

		if err := s.publishEnrichment(ctx, target, wafName); err != nil {
			return fmt.Errorf("failed to publish enrichment: %w", err)
		}
	} else {
		s.logger.Debug("No WAF detected",
			zap.String("trace_id", target.TraceID),
			zap.String("target", target.TargetURL),
		)
	}

	return nil
}

// publishEnrichment publishes WAF enrichment data to Redis stream
func (s *Service) publishEnrichment(ctx context.Context, target DetectionTarget, wafName string) error {
	// Create enrichment finding
	enrichment := shared.EnrichmentFinding{
		TraceID:        target.TraceID,
		ScanID:         target.ScanID,
		OrgID:          target.OrgID,
		Source:         "waf_detector",
		DiscoveryID:    target.DiscoveryID,
		EnrichmentType: "waf",
		Data: map[string]interface{}{
			"waf_name": wafName,
		},
		Timestamp: time.Now(),
	}

	// Marshal to JSON
	data, err := json.Marshal(enrichment)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment: %w", err)
	}

	// Publish to asset_enrichment_results stream
	_, err = s.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: shared.StreamAssetEnrichmentResults,
		Values: map[string]interface{}{
			"data": string(data),
		},
	}).Result()

	if err != nil {
		return fmt.Errorf("failed to publish to stream: %w", err)
	}

	s.logger.Info("Published WAF enrichment",
		zap.String("trace_id", target.TraceID),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("waf_name", wafName),
	)

	return nil
}

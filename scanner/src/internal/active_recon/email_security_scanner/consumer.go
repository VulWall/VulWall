package email_security_scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Consumer represents the email security scanner consumer
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new email security scanner consumer
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) (*Consumer, error) {
	service := NewService(redisClient, logger)

	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}, nil
}

// Start starts the consumer (domain scan triggers only - domains and subdomains)
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting EmailSecurityScanner consumer")

	// Create consumer group for domain scan triggers (start from latest — triggers are ephemeral)
	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamDomainScanTriggers, GroupEmailSecurityScanner); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamDomainScanTriggers,
		Group:          GroupEmailSecurityScanner,
		ConsumerPrefix: "email-security-scanner",
		BatchSize:      ConsumerBatchSize,
		Handler:        c.handleMessage,
		Logger:         c.logger,
	})
}

// handleMessage handles a single message from domain_scan_triggers
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("invalid message format: missing data field")
	}

	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal discovery finding: %w", err)
	}

	// Extract trace context
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Only process domains and subdomains
	if finding.AssetType != shared.AssetTypeDomain && finding.AssetType != shared.AssetTypeSubdomain {
		c.logger.Debug("Skipping non-domain asset",
			zap.String("asset_type", finding.AssetType),
			zap.String("host", finding.Host),
		)
		return nil
	}

	scanTarget := ScanTarget{
		Target:      finding.Host,
		AssetType:   finding.AssetType,
		DiscoveryID: finding.DiscoveryID,
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
	}

	return c.service.ProcessDiscovery(ctx, scanTarget)
}

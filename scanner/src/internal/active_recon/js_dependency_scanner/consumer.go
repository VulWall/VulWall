package js_dependency_scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Consumer represents the JSDependencyScanner consumer
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new JSDependencyScanner consumer
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
	c.logger.Info("Starting JSDependencyScanner consumer")

	// Create consumer group for domain scan triggers (start from latest — triggers are ephemeral)
	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamDomainScanTriggers, GroupJSDependencyScanner); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamDomainScanTriggers,
		Group:          GroupJSDependencyScanner,
		ConsumerPrefix: "js-dependency-scanner",
		BatchSize:      ConsumerBatchSize,
		Handler:        c.handleDomainMessage,
		Logger:         c.logger,
	})
}

// handleDomainMessage handles a single message from domain_scan_triggers
func (c *Consumer) handleDomainMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("invalid message format: missing data field"))
	}

	// Parse discovery finding
	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return redisx.Permanent(fmt.Errorf("failed to unmarshal discovery finding: %w", err))
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Only process domains and subdomains (skip IPs and ports)
	if finding.AssetType != shared.AssetTypeDomain && finding.AssetType != shared.AssetTypeSubdomain {
		c.logger.Debug("Skipping non-domain asset",
			zap.String("asset_type", finding.AssetType),
			zap.String("host", finding.Host),
		)
		return nil
	}

	// Build target (domain or subdomain)
	target := finding.Host

	// Create scan target
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // domain or subdomain
		DiscoveryID: finding.DiscoveryID, // Use actual discovery UUID from discoveries collection
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
		Unresolved:  finding.IP == nil || *finding.IP == "", // coverage is an error then
	}

	// Process the discovery
	return c.service.ProcessDiscovery(ctx, scanTarget)
}

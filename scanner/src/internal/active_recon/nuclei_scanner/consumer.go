package nuclei_scanner

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

// Consumer consumes discovery results from both domain and IP streams
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new Nuclei scanner consumer
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) *Consumer {
	service := NewService(redisClient, logger)
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming messages from both discovery streams concurrently
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting Nuclei scanner consumer")

	// Start template updater in background (cron-based)
	go c.service.StartTemplateUpdater(ctx)

	// Create consumer groups for both trigger streams (start from latest — triggers are ephemeral)
	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamDomainScanTriggers, GroupNucleiScanner); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamPortScanTriggers, GroupNucleiScanner); err != nil {
		return fmt.Errorf("failed to create IP consumer group: %w", err)
	}

	errChan := make(chan error, 2)

	go func() {
		errChan <- redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
			Stream:         shared.StreamDomainScanTriggers,
			Group:          GroupNucleiScanner,
			ConsumerPrefix: "nuclei-domain",
			BatchSize:      ConsumerBatchSize,
			Handler:        c.handleDomainMessage,
			Logger:         c.logger,
		})
	}()

	go func() {
		errChan <- redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
			Stream:         shared.StreamPortScanTriggers,
			Group:          GroupNucleiScanner,
			ConsumerPrefix: "nuclei-ip",
			BatchSize:      ConsumerBatchSize,
			Handler:        c.handleIPMessage,
			Logger:         c.logger,
		})
	}()

	// Return the first non-cancellation error, or wait for both to finish
	return <-errChan
}

// handleDomainMessage processes a single domain discovery finding message
func (c *Consumer) handleDomainMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse discovery finding
	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal finding: %w", err)
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

	// Build target URL based on discovery type
	var target string
	if finding.IP != nil && *finding.IP != "" {
		// If we have an IP, scan the IP
		if finding.Port != nil && *finding.Port > 0 {
			// Port-specific scan
			protocol := "http"
			if *finding.Port == 443 {
				protocol = "https"
			}
			target = fmt.Sprintf("%s://%s:%d", protocol, *finding.IP, *finding.Port)
		} else {
			// IP-only scan
			target = *finding.IP
		}
	} else {
		// Domain/subdomain scan
		target = finding.Host
	}

	// Create scan target using the discovery_id from the finding
	// The discovery service already generated a deterministic ID for this asset
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // Asset type (domain, subdomain, ip, port)
		DiscoveryID: finding.DiscoveryID, // Use the ID from the finding
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,      // Pass through scan_id
		OrgID:       finding.OrgID,
	}

	// Process the scan
	return c.service.ProcessDiscovery(ctx, scanTarget)
}

// handleIPMessage processes a single IP discovery finding message
func (c *Consumer) handleIPMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse IP discovery finding
	var finding shared.IPDiscoveryFinding
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal IP finding: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping IP finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Build target URL
	protocol := "http"
	if finding.Port == 443 || finding.Port == 8443 {
		protocol = "https"
	}
	target := fmt.Sprintf("%s://%s:%d", protocol, finding.IP, finding.Port)

	// Use the discovery_id from the finding
	// The port scanner already generated a deterministic ID for this port
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // Asset type (port)
		DiscoveryID: finding.DiscoveryID, // Use the ID from the finding
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,      // Pass through scan_id
		OrgID:       finding.OrgID,
	}

	// Process the scan
	return c.service.ProcessDiscovery(ctx, scanTarget)
}


package nuclei_scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.uber.org/zap"
)

// Consumer consumes scan triggers from both the domain and the port trigger
// streams.
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
	workers int
	// slots limits concurrent nuclei processes across both streams.
	slots chan struct{}
}

// NewConsumer creates a new Nuclei scanner consumer
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) *Consumer {
	workers := config.GetEnvInt(config.EnvNucleiWorkers, DefaultWorkers)
	if workers < 1 {
		workers = DefaultWorkers
	}
	return &Consumer{
		redis:   redisClient,
		service: NewService(redisClient, logger),
		logger:  logger,
		workers: workers,
		slots:   make(chan struct{}, workers),
	}
}

// Start begins consuming messages from both trigger streams concurrently
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting Nuclei scanner consumer", zap.Int("workers", c.workers))

	// Create consumer groups for both trigger streams (start from latest — triggers are ephemeral)
	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamDomainScanTriggers, GroupNucleiScanner); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamPortScanTriggers, GroupNucleiScanner); err != nil {
		return fmt.Errorf("failed to create IP consumer group: %w", err)
	}

	// Install or update templates before reading any trigger. On first boot the
	// templates directory is empty, and a scan without templates finds nothing.
	// Triggers published meanwhile wait in the stream (the group exists), and
	// the scan monitor keeps the scan open until they are consumed.
	c.service.updateTemplates(ctx)
	go c.service.StartTemplateUpdater(ctx)

	errChan := make(chan error, 2)

	go func() {
		errChan <- redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
			Stream:         shared.StreamDomainScanTriggers,
			Group:          GroupNucleiScanner,
			ConsumerPrefix: "nuclei-domain",
			BatchSize:      ConsumerBatchSize,
			Concurrency:    c.workers,
			Handler:        c.limited(c.handleDomainMessage),
			Logger:         c.logger,
		})
	}()

	go func() {
		errChan <- redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
			Stream:         shared.StreamPortScanTriggers,
			Group:          GroupNucleiScanner,
			ConsumerPrefix: "nuclei-ip",
			BatchSize:      ConsumerBatchSize,
			Concurrency:    c.workers,
			Handler:        c.limited(c.handleIPMessage),
			Logger:         c.logger,
		})
	}()

	// Return the first non-cancellation error, or wait for both to finish
	return <-errChan
}

// limited wraps a handler so that at most c.workers nuclei scans run at once,
// counted across both streams.
func (c *Consumer) limited(handler redisx.MessageHandler) redisx.MessageHandler {
	return func(ctx context.Context, message redis.XMessage) error {
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		defer func() { <-c.slots }()
		return handler(ctx, message)
	}
}

// handleDomainMessage processes a single domain discovery finding message
func (c *Consumer) handleDomainMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("message data is not a string"))
	}

	// Parse discovery finding
	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return redisx.Permanent(fmt.Errorf("failed to unmarshal finding: %w", err))
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

	if finding.Host == "" {
		c.logger.Warn("Skipping finding without host",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	return c.service.ProcessDiscovery(ctx, domainScanTarget(finding))
}

// domainScanTarget is the nuclei target of a domain or subdomain discovery.
//
// It is the hostname, not the IP it resolved to: behind a CDN, WAF or virtual host only a
// request that names the site (TLS SNI and Host header) reaches it; the bare IP gets a 403 or
// no TLS certificate, and nuclei drops it as unresponsive. nuclei probes https and http for a
// bare host itself. ProcessDiscovery checks that every address of the name is public before
// the run, and -lna refuses private addresses at dial time.
func domainScanTarget(finding shared.DiscoveryFinding) ScanTarget {
	return ScanTarget{
		Target:      finding.Host,
		AssetType:   finding.AssetType,   // domain or subdomain
		DiscoveryID: finding.DiscoveryID, // findings and coverage keep the domain discovery's id
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
		Unresolved:  finding.IP == nil || *finding.IP == "",
	}
}

// handleIPMessage processes a single IP discovery finding message
func (c *Consumer) handleIPMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("message data is not a string"))
	}

	// Parse IP discovery finding
	var finding shared.IPDiscoveryFinding
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return redisx.Permanent(fmt.Errorf("failed to unmarshal IP finding: %w", err))
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


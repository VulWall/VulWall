package nuclei_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
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

	// Create consumer groups for both streams
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDomainDiscoveryResults, GroupNucleiScanner); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupNucleiScanner); err != nil {
		return fmt.Errorf("failed to create IP consumer group: %w", err)
	}

	// Generate unique consumer names for this worker
	domainConsumerName := "nuclei-domain-" + uuid.New().String()
	ipConsumerName := "nuclei-ip-" + uuid.New().String()

	c.logger.Info("Consumer groups created",
		zap.String("domain_consumer", domainConsumerName),
		zap.String("ip_consumer", ipConsumerName),
	)

	// Create wait group to manage both goroutines
	var wg sync.WaitGroup
	errChan := make(chan error, 2) // Buffer for 2 consumers

	// Start domain discovery results consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.logger.Info("Starting domain discovery consumer")
		if err := c.processDomainMessages(ctx, domainConsumerName); err != nil && err != context.Canceled {
			errChan <- fmt.Errorf("domain consumer: %w", err)
		}
	}()

	// Start IP discovery results consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.logger.Info("Starting IP discovery consumer")
		if err := c.processIPMessages(ctx, ipConsumerName); err != nil && err != context.Canceled {
			errChan <- fmt.Errorf("IP consumer: %w", err)
		}
	}()

	// Wait for either all goroutines to finish or an error to occur
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Return the first error that occurs
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// processDomainMessages processes messages from domain_discovery_results stream
func (c *Consumer) processDomainMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Domain consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from domain discovery results stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupNucleiScanner,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainDiscoveryResults, ">"},
				Count:    1,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					// No messages available
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				c.logger.Error("Failed to read from domain stream", zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleDomainMessage(ctx, message); err != nil {
						c.logger.Error("Failed to process domain message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamDomainDiscoveryResults, GroupNucleiScanner, message.ID)
				}
			}
		}
	}
}

// processIPMessages processes messages from ip_discovery_results stream
func (c *Consumer) processIPMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("IP consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from IP discovery results stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupNucleiScanner,
				Consumer: consumerName,
				Streams:  []string{shared.StreamIPDiscoveryResults, ">"},
				Count:    1,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					// No messages available
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				c.logger.Error("Failed to read from IP stream", zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleIPMessage(ctx, message); err != nil {
						c.logger.Error("Failed to process IP message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamIPDiscoveryResults, GroupNucleiScanner, message.ID)
				}
			}
		}
	}
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


package testssl_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Consumer consumes discovery results from both domain and IP streams
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new testssl scanner consumer
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
	c.logger.Info("Starting testssl scanner consumer")

	// Create consumer groups for both streams
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDomainDiscoveryResults, GroupTestSSLScanner); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupTestSSLScanner); err != nil {
		return fmt.Errorf("failed to create IP consumer group: %w", err)
	}

	// Generate unique consumer names for this worker
	domainConsumerName := "testssl-domain-" + uuid.New().String()
	ipConsumerName := "testssl-ip-" + uuid.New().String()

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
				Group:    GroupTestSSLScanner,
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
					c.redis.XAck(ctx, shared.StreamDomainDiscoveryResults, GroupTestSSLScanner, message.ID)
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
				Group:    GroupTestSSLScanner,
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
					c.redis.XAck(ctx, shared.StreamIPDiscoveryResults, GroupTestSSLScanner, message.ID)
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

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// testssl.sh is specifically for TLS/SSL scanning
	// Only scan HTTPS targets or known SSL/TLS ports
	var target string

	if finding.IP != nil && *finding.IP != "" {
		// If we have an IP with a port
		if finding.Port != nil && *finding.Port > 0 {
			// Only scan SSL/TLS ports
			if !isSSLPort(*finding.Port) {
				c.logger.Debug("Skipping non-SSL port for testssl scan",
					zap.String("ip", *finding.IP),
					zap.Int("port", *finding.Port),
				)
				return nil
			}

			// Format: IP:port
			target = fmt.Sprintf("%s:%d", *finding.IP, *finding.Port)
		} else {
			// IP without port - default to 443
			target = fmt.Sprintf("%s:443", *finding.IP)
		}
	} else {
		// Domain/subdomain - scan on port 443 (HTTPS)
		target = fmt.Sprintf("%s:443", finding.Host)
	}

	// Create scan target - use discovery ID directly from finding
	// Discovery services always include this ID
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // Asset type (domain, subdomain, ip, port)
		DiscoveryID: finding.DiscoveryID, // Always present from discovery services
		TraceID:     finding.TraceID,
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

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping IP finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Only scan SSL/TLS ports
	if !isSSLPort(finding.Port) {
		c.logger.Debug("Skipping non-SSL port for testssl scan",
			zap.String("ip", finding.IP),
			zap.Int("port", finding.Port),
		)
		return nil
	}

	// Build target (format: IP:port)
	target := fmt.Sprintf("%s:%d", finding.IP, finding.Port)

	// Create scan target - use discovery ID directly from finding
	// Port discovery service always includes this ID
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // Asset type (port)
		DiscoveryID: finding.DiscoveryID, // Always present from port discovery service
		TraceID:     finding.TraceID,
		OrgID:       finding.OrgID,
	}

	// Process the scan
	return c.service.ProcessDiscovery(ctx, scanTarget)
}

// isSSLPort checks if a port is a common SSL/TLS port
func isSSLPort(port int) bool {
	sslPorts := []int{443, 8443, 465, 993, 995, 636, 989, 990, 992, 3389, 5986}
	for _, p := range sslPorts {
		if port == p {
			return true
		}
	}
	return false
}

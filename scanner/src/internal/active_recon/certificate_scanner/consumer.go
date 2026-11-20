package certificate_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Consumer reads both trigger streams: domains and subdomains are checked on 443 by
// hostname, open TLS ports (tlsPorts) by IP.
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates the certificate scanner consumer.
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) *Consumer {
	return &Consumer{redis: redisClient, service: NewService(redisClient, logger), logger: logger}
}

// Start consumes domain_scan_triggers and port_scan_triggers until ctx ends or one of them
// fails.
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting certificate scanner consumer",
		zap.Int("warn_days", c.service.limits.warn),
		zap.Int("critical_days", c.service.limits.critical),
	)
	streams := []struct {
		stream, prefix string
		handler        redisx.MessageHandler
	}{
		{shared.StreamDomainScanTriggers, "certificate-domain", c.handleDomainMessage},
		{shared.StreamPortScanTriggers, "certificate-port", c.handlePortMessage},
	}
	for _, s := range streams {
		if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, s.stream, GroupCertificateScanner); err != nil {
			return fmt.Errorf("create consumer group on %s: %w", s.stream, err)
		}
	}

	errs := make(chan error, len(streams))
	for _, s := range streams {
		go func() {
			errs <- redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
				Stream:         s.stream,
				Group:          GroupCertificateScanner,
				ConsumerPrefix: s.prefix,
				BatchSize:      ConsumerBatchSize,
				Concurrency:    ConsumerConcurrency,
				Handler:        s.handler,
				Logger:         c.logger,
			})
		}()
	}
	return <-errs
}

// handleDomainMessage checks <host>:443 of a domain or subdomain, with the hostname as SNI.
func (c *Consumer) handleDomainMessage(ctx context.Context, message redis.XMessage) error {
	var finding shared.DiscoveryFinding
	if err := decode(message, &finding); err != nil {
		return err
	}
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)
	target, ok := domainTarget(finding)
	if !ok {
		c.logger.Debug("Skipping domain trigger", zap.String("message_id", message.ID),
			zap.String("asset_type", finding.AssetType), zap.Bool("has_org", finding.OrgID != ""))
		return nil
	}
	return c.service.ProcessTarget(ctx, target, finding.Host)
}

// handlePortMessage checks an open TLS port by IP, without SNI.
func (c *Consumer) handlePortMessage(ctx context.Context, message redis.XMessage) error {
	var finding shared.IPDiscoveryFinding
	if err := decode(message, &finding); err != nil {
		return err
	}
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)
	target, ok := portTarget(finding)
	if !ok {
		return nil
	}
	return c.service.ProcessTarget(ctx, target, "")
}

// decode unmarshals the data field of a trigger message.
func decode(message redis.XMessage, v any) error {
	data, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("message data is not a string"))
	}
	if err := json.Unmarshal([]byte(data), v); err != nil {
		return redisx.Permanent(fmt.Errorf("unmarshal trigger: %w", err))
	}
	return nil
}

// domainTarget is the check of a domain or subdomain trigger: <host>:443. Other triggers and
// triggers without org_id or host get none.
func domainTarget(f shared.DiscoveryFinding) (ScanTarget, bool) {
	if f.OrgID == "" || f.Host == "" ||
		(f.AssetType != shared.AssetTypeDomain && f.AssetType != shared.AssetTypeSubdomain) {
		return ScanTarget{}, false
	}
	return ScanTarget{
		Target:      net.JoinHostPort(f.Host, "443"),
		AssetType:   f.AssetType,
		DiscoveryID: f.DiscoveryID,
		TraceID:     f.TraceID,
		ScanID:      f.ScanID,
		OrgID:       f.OrgID,
		Unresolved:  f.IP == nil || *f.IP == "", // coverage is an error then
	}, true
}

// portTarget is the check of an open port: <ip>:<port> for a port in tlsPorts. A CDN edge
// port (ScanHost set) gets none: by IP the edge serves no site's certificate, and the name
// port ingestion picked can change between scans, so its result would not be evidence for
// the port (see nuclei's ProcessCDNPort).
func portTarget(f shared.IPDiscoveryFinding) (ScanTarget, bool) {
	if f.OrgID == "" || f.IP == "" || f.ScanHost != "" || !tlsPorts[f.Port] {
		return ScanTarget{}, false
	}
	return ScanTarget{
		Target:      net.JoinHostPort(f.IP, strconv.Itoa(f.Port)),
		AssetType:   f.AssetType,
		DiscoveryID: f.DiscoveryID,
		TraceID:     f.TraceID,
		ScanID:      f.ScanID,
		OrgID:       f.OrgID,
	}, true
}

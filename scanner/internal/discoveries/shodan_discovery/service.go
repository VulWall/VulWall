package shodan_discovery

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/ingestion"
	"github.com/vulwall/scanners/internal/shared"
	"github.com/vulwall/scanners/internal/discoveries/shodan_discovery/shodan"
	"go.uber.org/zap"
)

type Service struct {
	redis        *redis.Client
	logger       *zap.Logger
	shodanClient *shodan.Client
}

func NewService(redisClient *redis.Client, shodanAPIKey string, logger *zap.Logger) *Service {
	return &Service{
		redis:        redisClient,
		logger:       logger,
		shodanClient: shodan.NewClient(shodanAPIKey, logger),
	}
}

// ProcessJob processes a discovery job using Shodan
func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
	s.logger.Info("Processing discovery job with Shodan",
		zap.String("trace_id", job.TraceID),
		zap.String("host", job.Host),
	)

	now := time.Now()

	// Publish root asset finding
	if err := s.publishFinding(ctx, ingestion.DiscoveryFinding{
		TraceID:   job.TraceID,
		Source:    "shodan",
		ParentID:  job.ParentID,
		Host:      job.Host,
		Port:      job.Port,
		Protocol:  job.Protocol,
		Status:    shared.AssetStatusActive,
		Metadata:  job.Metadata,
		Timestamp: now,
	}); err != nil {
		return err
	}

	// Trigger Shodan subdomain discovery for root domains (no parent, no port)
	if job.ParentID == nil && job.Port == nil && s.isDomain(job.Host) {
		go func() {
			if err := s.discoverSubdomains(context.Background(), job.TraceID, job.Host); err != nil {
				s.logger.Error("Shodan subdomain discovery failed",
					zap.String("host", job.Host),
					zap.Error(err),
				)
			}
		}()
	}

	return nil
}

// discoverSubdomains uses Shodan to discover and publish subdomain findings
func (s *Service) discoverSubdomains(ctx context.Context, traceID, domain string) error {
	s.logger.Info("Starting Shodan subdomain discovery",
		zap.String("trace_id", traceID),
		zap.String("domain", domain),
	)

	// Discover subdomains using Shodan
	subdomains, err := s.shodanClient.DiscoverSubdomains(ctx, domain)
	if err != nil {
		return err
	}

	if len(subdomains) == 0 {
		s.logger.Info("No subdomains discovered", zap.String("domain", domain))
		return nil
	}

	now := time.Now()
	parentHost := domain // Use the domain as parent identifier

	// Publish each discovered subdomain
	for _, subdomainName := range subdomains {
		// Skip empty strings and wildcards
		if subdomainName == "" || subdomainName == "*" {
			continue
		}

		// Build the full subdomain
		fullSubdomain := subdomainName
		if !contains(subdomainName, domain) {
			fullSubdomain = subdomainName + "." + domain
		}

		// Publish subdomain finding
		if err := s.publishFinding(ctx, ingestion.DiscoveryFinding{
			TraceID:   traceID,
			Source:    "shodan",
			ParentID:  &parentHost,
			Host:      fullSubdomain,
			Port:      nil,
			Protocol:  nil,
			Status:    shared.AssetStatusActive,
			Metadata:  map[string]interface{}{"discovery_type": "subdomain"},
			Timestamp: now,
		}); err != nil {
			s.logger.Error("Failed to publish subdomain finding",
				zap.String("subdomain", fullSubdomain),
				zap.Error(err),
			)
			continue
		}

		s.logger.Info("Published subdomain finding",
			zap.String("subdomain", fullSubdomain),
		)
	}

	return nil
}

// publishFinding publishes a discovery finding to the vulwall:discoveries stream
func (s *Service) publishFinding(ctx context.Context, finding ingestion.DiscoveryFinding) error {
	data, err := json.Marshal(finding)
	if err != nil {
		s.logger.Error("Failed to marshal finding", zap.Error(err))
		return err
	}

	_, err = s.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: shared.StreamDiscoveries,
		Values: map[string]interface{}{
			"data": string(data),
		},
	}).Result()

	if err != nil {
		s.logger.Error("Failed to publish finding to stream",
			zap.String("stream", shared.StreamDiscoveries),
			zap.Error(err),
		)
		return err
	}

	s.logger.Debug("Published finding to stream",
		zap.String("stream", shared.StreamDiscoveries),
		zap.String("host", finding.Host),
		zap.String("source", finding.Source),
	)

	return nil
}

// isDomain checks if the host is a domain (simple heuristic)
func (s *Service) isDomain(host string) bool {
	// Simple heuristic: if it contains only numbers and dots, it's an IP
	for _, c := range host {
		if !(c >= '0' && c <= '9' || c == '.') {
			return true
		}
	}
	return false
}

// contains checks if a string contains a substring (for subdomain building)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[len(s)-len(substr)-1:] == "."+substr || s[:len(substr)+1] == substr+"."))
}

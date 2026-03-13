package webtechprofiler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service represents the WebTechProfiler service
type Service struct {
	redis      *redis.Client
	logger     *zap.Logger
	wappalyzer *wappalyzer.Wappalyze
	httpClient *http.Client
	tracer     trace.Tracer
}

// NewService creates a new WebTechProfiler service
func NewService(redisClient *redis.Client, logger *zap.Logger) (*Service, error) {
	// Initialize Wappalyzer (underlying technology detection library)
	wappalyzerInstance, err := wappalyzer.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize wappalyzer: %w", err)
	}

	// Create HTTP client with timeout, TLS config, and SSRF-safe dialer.
	// SSRFSafeDialContext resolves DNS once, validates all returned IPs against
	// the full reserved-range list, then dials directly by IP — closing the
	// DNS-rebinding TOCTOU gap that would otherwise allow a second OS lookup
	// at connection time to return a private address.
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow self-signed certificates
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
			DialContext: shared.SSRFSafeDialContext(&net.Dialer{
				Timeout: 10 * time.Second,
			}),
		},
	}

	return &Service{
		redis:      redisClient,
		logger:     logger,
		wappalyzer: wappalyzerInstance,
		httpClient: httpClient,
		tracer:     otel.Tracer("webtechprofiler"),
	}, nil
}

// ProcessDiscovery processes a discovery target and detects web technologies
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	ctx, span := s.tracer.Start(ctx, "webtechprofiler",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
		),
	)
	defer span.End()

	s.logger.Info("Processing discovery for WebTechProfiler scan",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Scan both HTTP and HTTPS
	protocols := []string{"http", "https"}
	detectedTechs := make(map[string]TechDetectionWithInfo)

	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, target.Target)

		// Detect technologies for this URL
		techs, err := s.detectTechnologies(ctx, url)
		if err != nil {
			s.logger.Debug("Failed to scan URL",
				zap.String("url", url),
				zap.Error(err),
			)
			continue
		}

		// Store unique technologies (deduplicate by name)
		for tech, info := range techs {
			if _, exists := detectedTechs[tech]; !exists {
				detectedTechs[tech] = TechDetectionWithInfo{
					Technology: tech,
					URL:        url,
					AppInfo:    info,
				}
			}
		}
	}

	span.SetAttributes(attribute.Int("technologies.count", len(detectedTechs)))
	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	// Convert and publish findings
	for _, tech := range detectedTechs {
		finding := s.convertToSecurityFinding(tech, target)
		finding.TraceContext = telemetry.InjectTraceContext(ctx)
		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish finding",
				zap.String("technology", tech.Technology),
				zap.Error(err),
			)
			continue
		}

		s.logger.Info("Published technology finding",
			zap.String("technology", tech.Technology),
			zap.String("url", tech.URL),
			zap.String("org_id", target.OrgID),
		)
	}

	return nil
}

// detectTechnologies fetches the webpage and detects technologies using Wappalyzer
func (s *Service) detectTechnologies(ctx context.Context, url string) (map[string]wappalyzer.AppInfo, error) {
	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	// Fetch the webpage
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Use Wappalyzer to fingerprint technologies with detailed info
	fingerprints := s.wappalyzer.FingerprintWithInfo(resp.Header, body)

	return fingerprints, nil
}

// convertToSecurityFinding converts a technology detection to a SecurityFinding
func (s *Service) convertToSecurityFinding(tech TechDetectionWithInfo, target ScanTarget) shared.SecurityFinding {
	// Determine severity based on technology name
	severity := s.determineSeverity(tech.Technology)

	// Create metadata with categories and icon
	metadata := map[string]interface{}{
		"url": tech.URL,
	}

	// Add categories if available
	if len(tech.AppInfo.Categories) > 0 {
		metadata["categories"] = tech.AppInfo.Categories
	}

	// Add icon if available (normalize to .png extension)
	if tech.AppInfo.Icon != "" {
		// Remove existing extension and add .png
		ext := filepath.Ext(tech.AppInfo.Icon)
		iconName := strings.TrimSuffix(tech.AppInfo.Icon, ext)
		metadata["icon"] = iconName + ".png"
	}

	// Add description if available
	if tech.AppInfo.Description != "" {
		metadata["description"] = tech.AppInfo.Description
	}

	// Add website if available
	if tech.AppInfo.Website != "" {
		metadata["website"] = tech.AppInfo.Website
	}

	// Add CPE if available
	if tech.AppInfo.CPE != "" {
		metadata["cpe"] = tech.AppInfo.CPE
	}

	// Create finding
	finding := shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,
		OrgID:       target.OrgID,
		Source:     "webtechprofiler",
		DiscoveryID: target.DiscoveryID,
		Severity:    severity,
		Title:       tech.Technology,
		Metadata:    metadata,
		Status:      shared.FindingStatusOpen,
		Timestamp:   time.Now(),
	}

	return finding
}

// determineSeverity determines the severity level for a detected technology
func (s *Service) determineSeverity(technology string) string {
	// Most technology detections are informational
	// This can be enhanced with version checking and vulnerability databases
	return shared.SeverityInfo
}

// publishFinding publishes a security finding to the Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 0)
}

package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"go.uber.org/zap"
)

// Scanner defines the interface for JavaScript dependency scanning
type Scanner interface {
	Scan(ctx context.Context, targetURL string) ([]ProcessedVulnerability, error)
}

// JSDependencyScanner implements the Scanner interface
type JSDependencyScanner struct {
	httpClient *http.Client
	logger     *zap.Logger
}

// NewScanner creates a new JavaScript dependency scanner
func NewScanner(logger *zap.Logger) *JSDependencyScanner {
	return &JSDependencyScanner{
		httpClient: CreateHTTPClient(),
		logger:     logger,
	}
}

// Scan performs a complete JavaScript dependency vulnerability scan on the target URL
// Steps:
// 1. Fetch HTML content
// 2. Extract JavaScript file URLs from HTML
// 3. Download JS files in parallel (20 concurrent workers)
// 4. Run retire.js vulnerability scanner
// 5. Parse and return vulnerabilities
func (s *JSDependencyScanner) Scan(ctx context.Context, targetURL string) ([]ProcessedVulnerability, error) {
	// Step 1: Fetch HTML
	htmlContent, err := FetchHTML(ctx, targetURL, s.httpClient, s.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch HTML: %w", err)
	}

	// Step 2: Extract JS file URLs
	jsFiles := ExtractJSFiles(htmlContent, targetURL, s.logger)
	if len(jsFiles) == 0 {
		s.logger.Debug("No JavaScript files found", zap.String("url", targetURL))
		return nil, nil
	}

	s.logger.Debug("Found JavaScript files",
		zap.String("url", targetURL),
		zap.Int("count", len(jsFiles)),
	)

	// Step 3: Download JS files in parallel
	tmpDir, fileMetadata, failedDownloads, err := DownloadFiles(ctx, jsFiles, s.httpClient, s.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to download JS files: %w", err)
	}
	defer os.RemoveAll(tmpDir) // Clean up temp directory

	// A script that did not download was not checked: the scan is incomplete, and the
	// caller must not treat a vulnerability that is missing now as fixed.
	var incomplete error
	if failedDownloads > 0 {
		incomplete = fmt.Errorf("%w: %d of %d JavaScript files did not download", ErrIncomplete, failedDownloads, len(jsFiles))
	}

	if len(fileMetadata) == 0 {
		s.logger.Debug("No JavaScript files downloaded successfully")
		return nil, incomplete
	}

	s.logger.Debug("Downloaded JavaScript files",
		zap.Int("count", len(fileMetadata)),
		zap.String("tmp_dir", tmpDir),
	)

	// Step 4: Run retire.js vulnerability scanner
	retireOutput, err := RunRetireJS(ctx, tmpDir, s.logger)
	if err != nil {
		incomplete = errors.Join(incomplete, fmt.Errorf("%w: %w", ErrIncomplete, err))
	}

	// Step 5: Process vulnerabilities
	if retireOutput != nil && len(retireOutput.Data) > 0 {
		vulnerabilities := ProcessVulnerabilities(retireOutput, fileMetadata, targetURL)
		s.logger.Info("Vulnerabilities detected",
			zap.String("url", targetURL),
			zap.Int("count", len(vulnerabilities)),
		)
		return vulnerabilities, incomplete
	}

	s.logger.Debug("No vulnerabilities found", zap.String("url", targetURL))
	return nil, incomplete
}

// ErrIncomplete marks a scan that returned what it found but did not check everything.
var ErrIncomplete = errors.New("scan incomplete")

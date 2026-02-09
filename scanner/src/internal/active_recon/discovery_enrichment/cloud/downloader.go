package cloud

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Downloader handles downloading cloud provider IP range files
type Downloader struct {
	dataDir    string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewDownloader creates a new downloader
func NewDownloader(dataDir string, logger *zap.Logger) *Downloader {
	return &Downloader{
		dataDir: dataDir,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// DownloadAll downloads IP range files for all enabled cloud sources
func (d *Downloader) DownloadAll(ctx context.Context, sources []CloudSource) error {
	// Ensure data directory exists
	if err := os.MkdirAll(d.dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	d.logger.Info("Starting cloud IP ranges download",
		zap.String("data_dir", d.dataDir),
		zap.Int("total_sources", len(sources)),
	)

	var lastErr error
	successCount := 0

	for _, source := range sources {
		if !source.Enabled {
			d.logger.Debug("Skipping disabled source",
				zap.String("provider", source.Name),
			)
			continue
		}

		if err := d.downloadSource(ctx, source); err != nil {
			d.logger.Error("Failed to download source",
				zap.String("provider", source.Name),
				zap.String("url", source.URL),
				zap.Error(err),
			)
			lastErr = err
			continue
		}

		successCount++
		d.logger.Info("Successfully downloaded source",
			zap.String("provider", source.Name),
			zap.String("file", source.FileName),
		)
	}

	if successCount == 0 {
		return fmt.Errorf("failed to download any cloud IP ranges: %w", lastErr)
	}

	d.logger.Info("Cloud IP ranges download completed",
		zap.Int("success", successCount),
		zap.Int("total", len(sources)),
	)

	return nil
}

// downloadSource downloads a single cloud provider's IP range file
func (d *Downloader) downloadSource(ctx context.Context, source CloudSource) error {
	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	// Execute request
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create destination file
	filePath := filepath.Join(d.dataDir, source.FileName)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy response body to file
	written, err := io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	d.logger.Debug("Downloaded file",
		zap.String("provider", source.Name),
		zap.String("path", filePath),
		zap.Int64("bytes", written),
	)

	return nil
}

// LoadFromDisk loads a previously downloaded file from disk
func (d *Downloader) LoadFromDisk(source CloudSource) ([]byte, error) {
	filePath := filepath.Join(d.dataDir, source.FileName)

	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", filePath)
		}
		return nil, fmt.Errorf("failed to access file: %w", err)
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	d.logger.Debug("Loaded file from disk",
		zap.String("provider", source.Name),
		zap.String("path", filePath),
		zap.Int("bytes", len(data)),
	)

	return data, nil
}

// FileExists checks if a downloaded file exists on disk
func (d *Downloader) FileExists(source CloudSource) bool {
	filePath := filepath.Join(d.dataDir, source.FileName)
	_, err := os.Stat(filePath)
	return err == nil
}

package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.uber.org/zap"
)

// JSFileMetadata tracks information about a downloaded JavaScript file
type JSFileMetadata struct {
	URL      string // Original URL
	Filename string // Local filename
}

// DownloadResult represents the result of a download operation
type downloadResult struct {
	metadata JSFileMetadata
	err      error
}

// DownloadFiles downloads JavaScript files in parallel using a worker pool
// Uses 20 concurrent goroutines for maximum throughput
// Implements retry logic with exponential backoff for transient failures
func DownloadFiles(ctx context.Context, jsFiles []string, httpClient *http.Client, logger *zap.Logger) (string, []JSFileMetadata, error) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "webvuln-scan-*")
	if err != nil {
		return "", nil, err
	}

	// Skip non-http(s) URLs
	var validURLs []string
	for _, jsURL := range jsFiles {
		if strings.HasPrefix(jsURL, "http://") || strings.HasPrefix(jsURL, "https://") {
			validURLs = append(validURLs, jsURL)
		}
	}

	if len(validURLs) == 0 {
		return tmpDir, nil, nil
	}

	// Worker pool configuration
	const numWorkers = 20
	jobs := make(chan downloadJob, len(validURLs))
	results := make(chan downloadResult, len(validURLs))

	// Start worker pool
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go downloadWorker(ctx, jobs, results, httpClient, logger, &wg)
	}

	// Send jobs to workers
	for i, jsURL := range validURLs {
		filename := fmt.Sprintf("file_%d_%s", i, SanitizeFilename(jsURL))
		filePath := filepath.Join(tmpDir, filename)

		jobs <- downloadJob{
			url:      jsURL,
			filePath: filePath,
			filename: filename,
		}
	}
	close(jobs)

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var fileMetadata []JSFileMetadata
	for result := range results {
		if result.err != nil {
			logger.Debug("Failed to download JS file",
				zap.String("url", result.metadata.URL),
				zap.Error(result.err),
			)
			continue
		}

		fileMetadata = append(fileMetadata, result.metadata)
	}

	return tmpDir, fileMetadata, nil
}

// downloadJob represents a download task
type downloadJob struct {
	url      string
	filePath string
	filename string
}

// downloadWorker processes download jobs from the jobs channel
func downloadWorker(ctx context.Context, jobs <-chan downloadJob, results chan<- downloadResult, httpClient *http.Client, logger *zap.Logger, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		// Use timeout context for each download
		downloadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

		// Download with retry logic
		err := downloadFileWithRetry(downloadCtx, job.url, job.filePath, httpClient, logger)

		cancel()

		results <- downloadResult{
			metadata: JSFileMetadata{
				URL:      job.url,
				Filename: job.filename,
			},
			err: err,
		}
	}
}

// downloadFileWithRetry attempts to download a file with exponential backoff retry logic
func downloadFileWithRetry(ctx context.Context, url, filePath string, httpClient *http.Client, logger *zap.Logger) error {
	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s
			backoff := time.Duration(1<<(attempt-1)) * time.Second

			logger.Debug("Retrying download",
				zap.String("url", url),
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff),
			)

			select {
			case <-time.After(backoff):
				// Continue with retry
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := downloadFile(ctx, url, filePath, httpClient)
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Only retry on transient errors
		if !isRetryableError(err) {
			logger.Debug("Non-retryable error, skipping retries",
				zap.String("url", url),
				zap.Error(err),
			)
			return err
		}
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// downloadFile downloads a file from a URL to a local path
func downloadFile(ctx context.Context, url, filePath string, httpClient *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Create file
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Copy content (limit to 10MB to prevent huge downloads)
	limitedReader := io.LimitReader(resp.Body, 10*1024*1024)
	_, err = io.Copy(out, limitedReader)
	return err
}

// isRetryableError determines if an error is transient and worth retrying
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common transient errors
	errStr := err.Error()

	// Network timeouts and connection errors are retryable
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "temporary failure") ||
		strings.Contains(errStr, "TLS handshake timeout") {
		return true
	}

	// Check for specific net.Error types
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	// HTTP 5xx errors are retryable (server errors)
	if strings.Contains(errStr, "HTTP 5") {
		return true
	}

	// HTTP 429 (too many requests) is retryable
	if strings.Contains(errStr, "HTTP 429") {
		return true
	}

	// Default: don't retry
	return false
}

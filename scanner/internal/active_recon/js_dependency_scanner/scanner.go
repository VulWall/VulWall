package js_dependency_scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulwall/scanners/internal/shared"
	"golang.org/x/net/html"
	"go.uber.org/zap"
)

// fetchHTML fetches HTML content from a URL
func fetchHTML(ctx context.Context, targetURL string, httpClient *http.Client, logger *zap.Logger) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// extractJSFiles extracts JavaScript file URLs from HTML
func extractJSFiles(htmlContent, baseURL string, logger *zap.Logger) []string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		logger.Error("Failed to parse HTML", zap.Error(err))
		return []string{}
	}

	var jsFiles []string
	seenFiles := make(map[string]bool)

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, attr := range n.Attr {
				if attr.Key == "src" && attr.Val != "" {
					// Resolve relative URLs
					resolvedURL := resolveURL(baseURL, attr.Val)
					if resolvedURL != "" && !seenFiles[resolvedURL] {
						seenFiles[resolvedURL] = true
						jsFiles = append(jsFiles, resolvedURL)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return jsFiles
}

// resolveURL resolves a potentially relative URL against a base URL
func resolveURL(baseURL, href string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(ref)
	return resolved.String()
}

// downloadJSFiles downloads JavaScript files to a temporary directory
func downloadJSFiles(ctx context.Context, jsFiles []string, httpClient *http.Client, logger *zap.Logger) (string, []JSFileMetadata, error) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "webvuln-scan-*")
	if err != nil {
		return "", nil, err
	}

	var fileMetadata []JSFileMetadata

	// Download each file
	for i, jsURL := range jsFiles {
		// Skip non-http(s) URLs
		if !strings.HasPrefix(jsURL, "http://") && !strings.HasPrefix(jsURL, "https://") {
			continue
		}

		// Create filename from URL
		filename := fmt.Sprintf("file_%d_%s", i, sanitizeFilename(jsURL))
		filepath := filepath.Join(tmpDir, filename)

		// Download file with timeout
		downloadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := downloadFile(downloadCtx, jsURL, filepath, httpClient)
		cancel()

		if err != nil {
			logger.Debug("Failed to download JS file",
				zap.String("url", jsURL),
				zap.Error(err),
			)
			continue
		}

		fileMetadata = append(fileMetadata, JSFileMetadata{
			URL:      jsURL,
			Filename: filename,
		})
	}

	return tmpDir, fileMetadata, nil
}

// sanitizeFilename creates a safe filename from a URL
func sanitizeFilename(jsURL string) string {
	parsed, err := url.Parse(jsURL)
	if err != nil {
		return "unknown.js"
	}

	filename := filepath.Base(parsed.Path)
	if filename == "" || filename == "/" || filename == "." {
		filename = "script.js"
	}

	// Ensure .js extension
	if !strings.HasSuffix(filename, ".js") {
		filename += ".js"
	}

	// Remove any path separators
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, "?", "_")
	filename = strings.ReplaceAll(filename, ":", "_")

	// Limit length
	if len(filename) > 100 {
		ext := filepath.Ext(filename)
		filename = filename[:100-len(ext)] + ext
	}

	return filename
}

// downloadFile downloads a file from a URL to a local path
func downloadFile(ctx context.Context, url, filepath string, httpClient *http.Client) error {
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
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Copy content (limit to 10MB to prevent huge downloads)
	limitedReader := io.LimitReader(resp.Body, 10*1024*1024)
	_, err = io.Copy(out, limitedReader)
	return err
}

// createHTTPClient creates an HTTP client with appropriate settings
func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow self-signed certificates
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulwall/scanners/internal/shared"
	"golang.org/x/net/html"
	"go.uber.org/zap"
)

// FetchHTML fetches HTML content from a URL
// No size limit per user requirements
func FetchHTML(ctx context.Context, targetURL string, httpClient *http.Client, logger *zap.Logger) (string, error) {
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

	// Read entire response body (no limit per user requirements)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ExtractJSFiles extracts JavaScript file URLs from HTML
func ExtractJSFiles(htmlContent, baseURL string, logger *zap.Logger) []string {
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

// CreateHTTPClient creates an HTTP client with optimized settings for scanning
func CreateHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Allow self-signed certificates
		},
		ResponseHeaderTimeout: 10 * time.Second, // Detect hung servers quickly
		TLSHandshakeTimeout:   10 * time.Second, // TLS negotiation timeout
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,               // Increased for parallel downloads
		IdleConnTimeout:       30 * time.Second,
	}

	// SSRFSafeDialContext resolves DNS once, validates every returned IP against
	// the full reserved-range list, then dials directly to the first safe IP.
	// This closes the DNS-rebinding TOCTOU gap: the OS never performs a second
	// lookup that could be rebound to a private address at connection time.
	transport.DialContext = shared.SSRFSafeDialContext(&net.Dialer{
		Timeout: 5 * time.Second, // Fast DNS/TCP connection timeout
	})

	return &http.Client{
		Timeout:   15 * time.Second, // Reduced from 30s for faster failure detection
		Transport: transport,
	}
}

// SanitizeFilename creates a safe filename from a URL
func SanitizeFilename(jsURL string) string {
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

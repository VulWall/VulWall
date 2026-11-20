package nuclei_scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

// rootCheckTimeout bounds the GET of the target root after a nuclei run.
const rootCheckTimeout = 15 * time.Second

// rootURLs returns the URLs whose answer shows what nuclei saw: the target itself when it is a
// URL, else https:// and then http:// for a bare host or IP.
func rootURLs(target string) []string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return []string{target}
	}
	return []string{"https://" + target + "/", "http://" + target + "/"}
}

// newRootClient is an HTTP client that dials through the SSRF guard and does not follow
// redirects: the first answer is what nuclei got.
func newRootClient() *http.Client {
	return &http.Client{
		Timeout: rootCheckTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			DialContext:           shared.SSRFSafeDialContext(&net.Dialer{Timeout: 5 * time.Second}),
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// rootBlocked GETs the target root once after the run. A 403, 429 or 5xx answer or a WAF
// challenge means nuclei's templates may have met the block, not the application, so the run
// is no evidence (shared.BlockedResponse). The first URL that answers decides. No answer at
// all (a non-HTTP port, a TLS-only service nuclei spoke to with its network templates) adds
// nothing: shared.Reachable already checked that the port still accepts connections.
func rootBlocked(ctx context.Context, client *http.Client, target string) error {
	for _, u := range rootURLs(target) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", shared.DefaultUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, shared.BlockedBodyPrefix))
		resp.Body.Close()
		return shared.BlockedResponse(u, resp.StatusCode, resp.Header, body)
	}
	return nil
}

// rootAnswers GETs the target root before a run and returns an error unless it answers and
// the answer is not a block (shared.BlockedResponse): no answer within rootCheckTimeout, a
// 403, 429 or 5xx (a CDN's "origin unreachable" 52x) or a WAF challenge.
func rootAnswers(ctx context.Context, client *http.Client, target string) error {
	var lastErr error
	for _, u := range rootURLs(target) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", shared.DefaultUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, shared.BlockedBodyPrefix))
		resp.Body.Close()
		return shared.BlockedResponse(u, resp.StatusCode, resp.Header, body)
	}
	return lastErr
}

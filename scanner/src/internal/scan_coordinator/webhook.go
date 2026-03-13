package scan_coordinator

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// WebhookNotifier sends scan completion notifications to the Dashboard via HTTP webhook.
// Designed to be easy to unplug: pass an empty webhookURL to disable entirely.
type WebhookNotifier struct {
	webhookURL string
	secret     string
	client     *http.Client
	logger     *zap.Logger
}

// webhookPayload matches the Dashboard's expected request body.
type webhookPayload struct {
	ScanID string `json:"scan_id"`
}

// NewWebhookNotifier creates a notifier. Pass empty webhookURL to disable.
func NewWebhookNotifier(webhookURL, secret string, logger *zap.Logger) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		secret:     secret,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// Enabled returns true if the webhook URL is configured.
func (w *WebhookNotifier) Enabled() bool {
	return w.webhookURL != ""
}

// NotifyScanComplete sends a scan-completed event to the Dashboard.
// Safe to call even when disabled (no-ops). Retries once on transient failures.
// Runs with its own timeout so it never blocks the caller indefinitely.
func (w *WebhookNotifier) NotifyScanComplete(scanID string) {
	if !w.Enabled() {
		return
	}

	// Use a detached timeout so parent cancellation doesn't kill the webhook mid-flight
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := w.send(ctx, scanID)
	if err == nil {
		return
	}

	w.logger.Warn("Webhook failed, retrying once",
		zap.String("scan_id", scanID),
		zap.Error(err),
	)

	// Single retry after 2 seconds
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		w.logger.Warn("Webhook retry cancelled (timeout)",
			zap.String("scan_id", scanID),
		)
		return
	}

	if err := w.send(ctx, scanID); err != nil {
		w.logger.Error("Webhook failed after retry, giving up",
			zap.String("scan_id", scanID),
			zap.Error(err),
		)
	}
}

// send performs the actual HTTP POST to the Dashboard.
func (w *WebhookNotifier) send(ctx context.Context, scanID string) error {
	body, err := json.Marshal(webhookPayload{ScanID: scanID})
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(body)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Webhook-Signature", sig)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		w.logger.Info("Webhook delivered",
			zap.String("scan_id", scanID),
			zap.Int("status_code", resp.StatusCode),
		)
		return nil
	}

	return fmt.Errorf("unexpected status %d", resp.StatusCode)
}

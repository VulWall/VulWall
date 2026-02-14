package scan_coordinator

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// APIServer exposes HTTP endpoints for on-demand scan triggering.
// Designed to be detachable — only depends on *Service, not on Scheduler internals.
type APIServer struct {
	service *Service
	server  *http.Server
	logger  *zap.Logger
}

// NewAPIServer creates a new API server on the given port.
func NewAPIServer(service *Service, logger *zap.Logger, port string) *APIServer {
	s := &APIServer{
		service: service,
		logger:  logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/scans", s.handleTriggerScan)
	mux.HandleFunc("GET /health", s.handleHealth)

	s.server = &http.Server{
		Addr:    net.JoinHostPort("", port),
		Handler: mux,
	}

	return s
}

// Start runs the HTTP server and shuts down gracefully when ctx is cancelled.
func (a *APIServer) Start(ctx context.Context) error {
	// Graceful shutdown when context is cancelled
	go func() {
		<-ctx.Done()
		a.logger.Info("Shutting down API server")
		a.server.Shutdown(context.Background())
	}()

	a.logger.Info("API server starting", zap.String("addr", a.server.Addr))

	if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

type triggerScanRequest struct {
	OrgID       string `json:"org_id"`
	TriggeredBy string `json:"triggered_by"`
}

type triggerScanResponse struct {
	ScanID string `json:"scan_id"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (a *APIServer) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	var req triggerScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	if req.OrgID == "" {
		a.writeJSON(w, http.StatusBadRequest, errorResponse{Error: "org_id is required"})
		return
	}

	if req.TriggeredBy == "" {
		a.writeJSON(w, http.StatusBadRequest, errorResponse{Error: "triggered_by is required"})
		return
	}

	scanID, err := a.service.TriggerScan(r.Context(), ScanRequest{
		OrgID:       req.OrgID,
		Type:        shared.ScanTypeRequested,
		TriggeredBy: req.TriggeredBy,
	})
	if err != nil {
		a.logger.Error("Failed to trigger scan",
			zap.String("org_id", req.OrgID),
			zap.Error(err),
		)
		a.writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to trigger scan"})
		return
	}

	a.logger.Info("On-demand scan triggered via API",
		zap.String("scan_id", scanID),
		zap.String("org_id", req.OrgID),
		zap.String("triggered_by", req.TriggeredBy),
	)

	a.writeJSON(w, http.StatusCreated, triggerScanResponse{ScanID: scanID})
}

func (a *APIServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (a *APIServer) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

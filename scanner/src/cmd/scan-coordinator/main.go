package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/logger"
	"github.com/vulwall/scanners/internal/core/mongox"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/scan_coordinator"
	"go.uber.org/zap"
)

func main() {
	// Load configuration
	appCfg, err := config.Load()
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	// Initialize logger
	if err := logger.Init(appCfg.Environment); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
	defer logger.Sync()

	logger.Log.Info("Starting Scan Coordinator",
		zap.String("service", "scan-coordinator"),
		zap.String("environment", appCfg.Environment),
	)

	// Create context for service lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize OpenTelemetry tracing
	tracerProvider, err := telemetry.InitTracing(ctx, "scan-coordinator", appCfg.Environment, logger.Log)
	if err != nil {
		logger.Log.Fatal("Failed to initialize tracing", zap.Error(err))
	}
	defer func() {
		if err := tracerProvider.Shutdown(context.Background()); err != nil {
			logger.Log.Error("Failed to shutdown tracer provider", zap.Error(err))
		}
	}()

	// Connect to Redis
	redisClient, err := redisx.NewClient(appCfg)
	if err != nil {
		logger.Log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redisClient.Close()

	// Connect to MongoDB
	db, err := mongox.NewClient(appCfg)
	if err != nil {
		logger.Log.Fatal("Failed to connect to MongoDB", zap.Error(err))
	}
	defer db.Client().Disconnect(ctx)

	// Create shared service (used by both scheduler and API)
	service := scan_coordinator.NewService(redisClient, db, logger.Log)

	// Create stream cleaner (scheduled via cron inside the scheduler)
	streamCleaner := scan_coordinator.NewStreamCleaner(redisClient, logger.Log)

	// Create scheduler (includes stream cleanup cron job)
	scheduler := scan_coordinator.NewScheduler(service, db, streamCleaner, logger.Log)

	// Create webhook notifier (empty URL = disabled)
	webhookURL := config.GetEnv(config.EnvDashboardWebhookURL, "")
	webhookSecret := config.GetEnv(config.EnvDashboardWebhookSecret, "")
	webhook := scan_coordinator.NewWebhookNotifier(webhookURL, webhookSecret, logger.Log)
	if webhook.Enabled() {
		logger.Log.Info("Dashboard webhook enabled", zap.String("url", webhookURL))
	}

	// Create scan monitor
	scanMonitor := scan_coordinator.NewScanMonitor(redisClient, db, webhook, logger.Log)

	// Create API server
	apiPort := config.GetEnv(config.EnvAPIPort, "8080")
	apiKey := config.GetEnv(config.EnvAPIKey, "")
	if apiKey == "" {
		env := config.GetEnv(config.EnvEnvironment, "development")
		if env == "production" {
			logger.Log.Fatal("NIGHTWATCH_API_KEY must be set in production")
		}
		logger.Log.Warn("NIGHTWATCH_API_KEY is not set — scan trigger API is unauthenticated")
	}
	apiServer := scan_coordinator.NewAPIServer(service, logger.Log, apiPort, apiKey)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start scheduler in goroutine (includes org scan scheduling + stream cleanup cron)
	go scheduler.Start(ctx)

	// Start scan monitor in goroutine (runs every 15 minutes)
	go scanMonitor.Start(ctx)

	// Start API server in goroutine
	go apiServer.Start(ctx)

	// Wait for shutdown signal
	<-sigChan
	logger.Log.Info("Received shutdown signal")
	cancel()

	logger.Log.Info("Scan Coordinator stopped")
}

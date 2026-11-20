package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/logger"
	"github.com/VulWall/VulWall/scanner/src/internal/core/mongox"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/scan_coordinator"
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

	// Create scan monitor
	scanMonitor := scan_coordinator.NewScanMonitor(redisClient, db, logger.Log)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start scheduler in goroutine (includes org scan scheduling + stream cleanup cron)
	go scheduler.Start(ctx)

	// Start scan monitor in goroutine (runs every 15 minutes)
	go scanMonitor.Start(ctx)

	// Start queued-scan poller (scans requested from the web UI)
	go service.StartQueuedScans(ctx)

	// Wait for shutdown signal
	<-sigChan
	logger.Log.Info("Received shutdown signal")
	cancel()

	logger.Log.Info("Scan Coordinator stopped")
}

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

	// Create scheduler
	scheduler := scan_coordinator.NewScheduler(redisClient, db, logger.Log)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start scheduler in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := scheduler.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case <-sigChan:
		logger.Log.Info("Received shutdown signal")
		cancel()
	case err := <-errChan:
		logger.Log.Error("Scheduler error", zap.Error(err))
		cancel()
	}

	logger.Log.Info("Scan Coordinator stopped")
}

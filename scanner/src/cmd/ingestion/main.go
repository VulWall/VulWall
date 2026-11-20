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
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion"
	"go.uber.org/zap"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	// Initialize logger
	if err := logger.Init(cfg.Environment); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
	defer logger.Sync()

	logger.Log.Info("Starting ingestion service",
		zap.String("service", "ingestion"),
		zap.String("environment", cfg.Environment),
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize OpenTelemetry tracing
	tracerProvider, err := telemetry.InitTracing(ctx, "ingestion", cfg.Environment, logger.Log)
	if err != nil {
		logger.Log.Fatal("Failed to initialize tracing", zap.Error(err))
	}
	defer func() {
		if err := tracerProvider.Shutdown(context.Background()); err != nil {
			logger.Log.Error("Failed to shutdown tracer provider", zap.Error(err))
		}
	}()

	// Initialize Redis client
	redisClient, err := redisx.NewClient(cfg)
	if err != nil {
		logger.Log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redisClient.Close()

	logger.Log.Info("Connected to Redis",
		zap.String("uri", cfg.RedisURI),
	)

	// Initialize MongoDB client
	db, err := mongox.NewClient(cfg)
	if err != nil {
		logger.Log.Fatal("Failed to connect to MongoDB", zap.Error(err))
	}

	logger.Log.Info("Connected to MongoDB",
		zap.String("database", cfg.MongoDB),
	)

	// Ensure indexes exist
	if err := mongox.EnsureIndexes(ctx, db, logger.Log); err != nil {
		logger.Log.Fatal("Failed to create indexes", zap.Error(err))
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start orchestrator in a goroutine
	orchestrator := ingestion.NewOrchestrator(redisClient, db, logger.Log)

	errChan := make(chan error, 1)
	go func() {
		if err := orchestrator.Start(ctx); err != nil && err != context.Canceled {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Log.Info("Received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	case err := <-errChan:
		logger.Log.Error("Orchestrator error", zap.Error(err))
		cancel()
	}

	logger.Log.Info("Ingestion service shutdown complete")
}

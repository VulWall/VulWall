package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/logger"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
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

	logger.Log.Info("Starting discovery enrichment service",
		zap.String("service", "discovery-enrichment"),
		zap.String("environment", cfg.Environment),
	)

	// Create context for service lifecycle
	ctx := context.Background()

	// Initialize OpenTelemetry tracing
	tracerProvider, err := telemetry.InitTracing(ctx, cfg.ServiceName, cfg.Environment, logger.Log)
	if err != nil {
		logger.Log.Warn("Failed to initialize tracing", zap.Error(err))
		// Continue without tracing rather than failing
	}
	if tracerProvider != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := tracerProvider.Shutdown(shutdownCtx); err != nil {
				logger.Log.Error("Failed to shutdown tracer", zap.Error(err))
			}
		}()
	}

	// Initialize Redis client
	redisClient, err := redisx.NewClient(cfg)
	if err != nil {
		logger.Log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redisClient.Close()

	logger.Log.Info("Connected to Redis",
		zap.String("uri", cfg.RedisURI),
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create and start consumer
	consumer, err := discovery_enrichment.NewConsumer(redisClient, cfg, logger.Log)
	if err != nil {
		logger.Log.Fatal("Failed to create consumer", zap.Error(err))
	}

	errChan := make(chan error, 1)
	go func() {
		if err := consumer.Start(ctx); err != nil && err != context.Canceled {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Log.Info("Received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	case err := <-errChan:
		logger.Log.Error("Consumer error", zap.Error(err))
		cancel()
	}

	logger.Log.Info("Discovery enrichment service shutdown complete")
}

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/logger"
	"github.com/vulwall/scanners/internal/core/redisx"
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
	ctx, cancel := context.WithCancel(context.Background())
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

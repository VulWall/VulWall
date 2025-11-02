package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vulwall/scanners/internal/active_recon/webtechprofiler"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/logger"
	"github.com/vulwall/scanners/internal/core/redisx"
	"go.uber.org/zap"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		panic("Failed to load configuration: " + err.Error())
	}

	// Initialize logger
	logger.Init(cfg.Environment)
	defer logger.Sync()

	logger.Log.Info("Starting WebTechProfiler Service",
		zap.String("environment", cfg.Environment),
	)

	// Initialize Redis client
	redisClient, err := redisx.NewClient(cfg)
	if err != nil {
		logger.Log.Fatal("Failed to initialize Redis client", zap.Error(err))
	}
	defer redisClient.Close()

	logger.Log.Info("Redis client initialized successfully")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create and start the consumer
	consumer, err := webtechprofiler.NewConsumer(redisClient, logger.Log)
	if err != nil {
		logger.Log.Fatal("Failed to create consumer", zap.Error(err))
	}

	logger.Log.Info("Consumer created successfully, starting message processing...")

	// Start consumer in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := consumer.Start(ctx); err != nil && err != context.Canceled {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Log.Info("Received shutdown signal, initiating graceful shutdown",
			zap.String("signal", sig.String()),
		)
		cancel()
	case err := <-errChan:
		logger.Log.Error("Consumer encountered an error",
			zap.Error(err),
		)
		cancel()
	}

	logger.Log.Info("WebTechProfiler Service stopped")
}

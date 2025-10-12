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
	"github.com/vulwall/scanners/internal/shared"
	"github.com/vulwall/scanners/internal/slices/attack_surface"
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

	logger.Log.Info("Starting attack surface service",
		zap.String("service", cfg.ServiceName),
		zap.String("environment", cfg.Environment),
	)

	// Connect to Redis
	redisClient, err := redisx.NewClient(cfg)
	if err != nil {
		logger.Log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redisClient.Close()

	// Connect to MongoDB
	db, err := mongox.NewClient(cfg)
	if err != nil {
		logger.Log.Fatal("Failed to connect to MongoDB", zap.Error(err))
	}

	// Create consumer group
	ctx := context.Background()
	if err := redisx.CreateConsumerGroup(ctx, redisClient, shared.StreamAttackSurface, shared.GroupAttackSurface); err != nil {
		logger.Log.Fatal("Failed to create consumer group", zap.Error(err))
	}

	// Create and start consumer
	consumer := attack_surface.NewConsumer(redisClient, db, logger.Log)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Log.Info("Received shutdown signal")
		os.Exit(0)
	}()

	// Start consuming
	if err := consumer.Start(ctx); err != nil {
		logger.Log.Fatal("Consumer error", zap.Error(err))
	}
}

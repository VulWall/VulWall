package bootstrap

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/logger"
	"github.com/vulwall/scanners/internal/core/mongox"
	"github.com/vulwall/scanners/internal/core/redisx"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// ConsumerStarter represents any consumer that can be started
type ConsumerStarter interface {
	Start(ctx context.Context) error
}

// ConsumerFactory is a function that creates a consumer instance
type ConsumerFactory func(cfg *config.Config, redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) ConsumerStarter

// ServiceConfig holds the configuration for bootstrapping a service
type ServiceConfig struct {
	ServiceName   string
	StreamName    string
	ConsumerGroup string
	Factory       ConsumerFactory
}

// Run bootstraps and runs a scanner service with the given configuration
func Run(cfg ServiceConfig) {
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

	logger.Log.Info("Starting service",
		zap.String("service", cfg.ServiceName),
		zap.String("environment", appCfg.Environment),
		zap.String("stream", cfg.StreamName),
	)

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

	// Create consumer group
	ctx := context.Background()
	if err := redisx.CreateConsumerGroup(ctx, redisClient, cfg.StreamName, cfg.ConsumerGroup); err != nil {
		logger.Log.Fatal("Failed to create consumer group", zap.Error(err))
	}

	// Create consumer using the factory function
	consumer := cfg.Factory(appCfg, redisClient, db, logger.Log)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Log.Info("Received shutdown signal")
		os.Exit(0)
	}()

	// Start consuming
	logger.Log.Info("Consumer started, waiting for messages...")
	if err := consumer.Start(ctx); err != nil {
		logger.Log.Fatal("Consumer error", zap.Error(err))
	}
}

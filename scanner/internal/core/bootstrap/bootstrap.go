package bootstrap

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/logger"
	"github.com/vulwall/scanners/internal/core/mongox"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
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

	// Create context for service lifecycle
	ctx := context.Background()

	// Initialize OpenTelemetry tracing
	tracerProvider, err := telemetry.InitTracing(ctx, appCfg.ServiceName, appCfg.Environment, logger.Log)
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

	// Create consumer group
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

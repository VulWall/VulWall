package bootstrap

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/logger"
	"github.com/VulWall/VulWall/scanner/src/internal/core/mongox"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/redis/go-redis/v9"
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
	redisx.CleanupStaleConsumers(ctx, redisClient, cfg.StreamName, cfg.ConsumerGroup, logger.Log)

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

// SimpleConsumerFactory is a function that creates a consumer with minimal dependencies
type SimpleConsumerFactory func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (ConsumerStarter, error)

// StreamConfig defines a stream and consumer group pair for automatic creation
type StreamConfig struct {
	StreamName    string
	ConsumerGroup string
}

// SimpleServiceConfig holds the configuration for bootstrapping a simple service
// Simple services don't need MongoDB. Consumer groups can be created automatically
// by specifying Streams, or handled by the service itself if Streams is empty.
type SimpleServiceConfig struct {
	ServiceName string
	Factory     SimpleConsumerFactory
	// Streams to create consumer groups for (optional)
	// If empty, service handles its own consumer group creation
	Streams []StreamConfig
}

// RunSimple bootstraps and runs a simple scanner service (no MongoDB, no consumer group management)
// This is suitable for dual-stream consumers and services with custom initialization needs
func RunSimple(cfg SimpleServiceConfig) {
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

	logger.Log.Info("Connected to Redis",
		zap.String("uri", appCfg.RedisURI),
	)

	// Create consumer groups if specified
	for _, stream := range cfg.Streams {
		if err := redisx.CreateConsumerGroup(ctx, redisClient, stream.StreamName, stream.ConsumerGroup); err != nil {
			logger.Log.Fatal("Failed to create consumer group",
				zap.String("stream", stream.StreamName),
				zap.String("group", stream.ConsumerGroup),
				zap.Error(err),
			)
		}
		redisx.CleanupStaleConsumers(ctx, redisClient, stream.StreamName, stream.ConsumerGroup, logger.Log)
		logger.Log.Info("Consumer group ready",
			zap.String("stream", stream.StreamName),
			zap.String("group", stream.ConsumerGroup),
		)
	}

	// Create consumer using the factory function
	consumer, err := cfg.Factory(appCfg, redisClient, logger.Log)
	if err != nil {
		logger.Log.Fatal("Failed to create consumer", zap.Error(err))
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start consumer in goroutine
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

	logger.Log.Info("Service shutdown complete",
		zap.String("service", cfg.ServiceName),
	)
}

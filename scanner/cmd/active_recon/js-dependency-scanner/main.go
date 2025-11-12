package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/active_recon/js_dependency_scanner"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func main() {
	bootstrap.Run(bootstrap.ServiceConfig{
		ServiceName:   "js-dependency-scanner",
		StreamName:    shared.StreamDomainDiscoveryResults,
		ConsumerGroup: js_dependency_scanner.GroupJSDependencyScanner,
		Factory: func(cfg *config.Config, redisClient *redis.Client, _ *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
			consumer, err := js_dependency_scanner.NewConsumer(redisClient, logger)
			if err != nil {
				logger.Fatal("Failed to create consumer", zap.Error(err))
			}
			return consumer
		},
	})
}

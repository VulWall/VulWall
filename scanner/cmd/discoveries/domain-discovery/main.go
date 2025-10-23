package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/shared"
	"github.com/vulwall/scanners/internal/discoveries/domain_discovery"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func main() {
	bootstrap.Run(bootstrap.ServiceConfig{
		ServiceName:   "domain-discovery",
		StreamName:    shared.StreamDomainDiscoveryQueue,
		ConsumerGroup: domain_discovery.GroupShodanSubdomainService,
		Factory: func(cfg *config.Config, redisClient *redis.Client, _ *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
			return domain_discovery.NewConsumer(redisClient, cfg.ShodanAPIKey, logger)
		},
	})
}

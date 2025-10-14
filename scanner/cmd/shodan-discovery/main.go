package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/shared"
	"github.com/vulwall/scanners/internal/discoveries/shodan_discovery"
	"go.uber.org/zap"
)

func main() {
	bootstrap.Run(bootstrap.ServiceConfig{
		ServiceName:   "shodan-discovery",
		StreamName:    shared.StreamDiscovery,
		ConsumerGroup: shodan_discovery.GroupShodanDiscovery,
		Factory: func(cfg *config.Config, redisClient *redis.Client, _ *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
			return shodan_discovery.NewConsumer(redisClient, cfg.ShodanAPIKey, logger)
		},
	})
}

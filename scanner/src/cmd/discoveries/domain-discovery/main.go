package main

import (
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/discoveries/domain_discovery"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "domain-discovery",
		Streams: []bootstrap.StreamConfig{
			{StreamName: shared.StreamDomainDiscoveryQueue, ConsumerGroup: domain_discovery.GroupShodanSubdomainService},
		},
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			return domain_discovery.NewConsumer(redisClient, logger)
		},
	})
}

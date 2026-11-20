package main

import (
	"github.com/VulWall/VulWall/scanner/src/internal/core/bootstrap"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/domain_discovery"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
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

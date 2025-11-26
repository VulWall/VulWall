package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/discoveries/port_discovery"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "port-discovery",
		Streams: []bootstrap.StreamConfig{
			{StreamName: shared.StreamIPDiscoveryQueue, ConsumerGroup: port_discovery.GroupPortDiscovery},
		},
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			return port_discovery.NewConsumer(redisClient, logger), nil
		},
	})
}

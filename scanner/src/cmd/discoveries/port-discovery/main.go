package main

import (
	"github.com/VulWall/VulWall/scanner/src/internal/core/bootstrap"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/port_discovery"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
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

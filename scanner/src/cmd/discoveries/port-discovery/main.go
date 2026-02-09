package main

import (
	"github.com/redis/go-redis/v9"
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
			// Get Shodan API key from config (used as primary source, TCP fallback if unavailable)
			shodanAPIKey := config.GetEnv(config.EnvShodanAPIKey, "")
			if shodanAPIKey == "" {
				logger.Warn("SHODAN_API_KEY not configured, port discovery will use TCP scanner only")
			}
			return port_discovery.NewConsumer(redisClient, shodanAPIKey, logger), nil
		},
	})
}

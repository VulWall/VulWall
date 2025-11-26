package main

import (
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/active_recon/discovery_enrichment"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "discovery-enrichment",
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			return discovery_enrichment.NewConsumer(redisClient, logger)
		},
	})
}

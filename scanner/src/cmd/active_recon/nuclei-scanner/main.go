package main

import (
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/active_recon/nuclei_scanner"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "nuclei-scanner",
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			return nuclei_scanner.NewConsumer(redisClient, logger), nil
		},
	})
}

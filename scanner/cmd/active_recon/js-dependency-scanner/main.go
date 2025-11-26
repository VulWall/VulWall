package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/active_recon/js_dependency_scanner"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "js-dependency-scanner",
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			return js_dependency_scanner.NewConsumer(redisClient, logger)
		},
	})
}

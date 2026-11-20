package main

import (
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/js_dependency_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/core/bootstrap"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/redis/go-redis/v9"
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

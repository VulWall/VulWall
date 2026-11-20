package main

import (
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/http_header_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/core/bootstrap"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "http-header-scanner",
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			return http_header_scanner.NewConsumer(redisClient, logger)
		},
	})
}

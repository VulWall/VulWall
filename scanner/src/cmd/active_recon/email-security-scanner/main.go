package main

import (
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/active_recon/email_security_scanner"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "email-security-scanner",
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			return email_security_scanner.NewConsumer(redisClient, logger)
		},
	})
}

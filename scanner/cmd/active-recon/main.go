package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/discoveries/active_recon"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func main() {
	bootstrap.Run(bootstrap.ServiceConfig{
		ServiceName:   "active-recon",
		StreamName:    active_recon.StreamActiveRecon,
		ConsumerGroup: active_recon.GroupActiveRecon,
		Factory: func(cfg *config.Config, redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
			return active_recon.NewConsumer(redisClient, db, logger)
		},
	})
}

package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/slices/passive_recon"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func main() {
	bootstrap.Run(bootstrap.ServiceConfig{
		ServiceName:   "passive-recon",
		StreamName:    passive_recon.StreamPassiveRecon,
		ConsumerGroup: passive_recon.GroupPassiveRecon,
		Factory: func(cfg *config.Config, redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
			return passive_recon.NewConsumer(redisClient, db, logger)
		},
	})
}

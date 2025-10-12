package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/shared"
	"github.com/vulwall/scanners/internal/slices/attack_surface"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func main() {
	bootstrap.Run(bootstrap.ServiceConfig{
		ServiceName:   "attack-surface",
		StreamName:    shared.StreamAttackSurface,
		ConsumerGroup: shared.GroupAttackSurface,
		Factory: func(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
			return attack_surface.NewConsumer(redisClient, db, logger)
		},
	})
}

package main

import (
	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/discoveries/port_discovery"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func main() {
	bootstrap.Run(bootstrap.ServiceConfig{
		ServiceName:   "port-discovery",
		StreamName:    shared.StreamIPDiscoveryQueue,
		ConsumerGroup: port_discovery.GroupPortDiscovery,
		Factory: func(cfg *config.Config, redisClient *redis.Client, _ *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
			return port_discovery.NewConsumer(redisClient, logger)
		},
	})
}

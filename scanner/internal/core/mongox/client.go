package mongox

import (
	"context"
	"time"

	"github.com/vulwall/scanners/internal/core/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewClient(cfg *config.Config) (*mongo.Database, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	return client.Database(cfg.MongoDB), nil
}

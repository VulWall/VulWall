package main

import (
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/core/bootstrap"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/enrichers/knowledge_base"
	"github.com/VulWall/VulWall/scanner/src/internal/enrichers/knowledge_base/anthropic"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "knowledge-base-engine",
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			// Get Anthropic API key from environment
			anthropicAPIKey := config.GetEnv(config.EnvAnthropicAPIKey, "")
			if anthropicAPIKey == "" {
				return nil, fmt.Errorf("ANTHROPIC_API_KEY environment variable is required")
			}

			// Get model (optional, defaults to claude-sonnet-4-5-20250514)
			anthropicModel := config.GetEnv(config.EnvAnthropicModel, anthropic.DefaultModel)

			// Create Anthropic client
			anthropicClient := anthropic.NewClient(anthropicAPIKey, anthropicModel, logger)

			// Create service
			service, err := knowledge_base.NewService(redisClient, anthropicClient, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to create service: %w", err)
			}

			// Create and return consumer
			return knowledge_base.NewConsumer(redisClient, service, logger), nil
		},
	})
}

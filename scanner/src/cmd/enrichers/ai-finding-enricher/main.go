package main

import (
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/bootstrap"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/enrichers/ai_finding_enricher"
	"github.com/vulwall/scanners/internal/enrichers/ai_finding_enricher/groq"
	"go.uber.org/zap"
)

func main() {
	bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
		ServiceName: "ai-finding-enricher",
		Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
			// Get Groq API key from environment
			groqAPIKey := config.GetEnv(config.EnvGroqAPIKey, "")
			if groqAPIKey == "" {
				return nil, fmt.Errorf("GROQ_API_KEY environment variable is required")
			}

			// Get model (optional, defaults to llama-3.3-70b-versatile)
			groqModel := config.GetEnv(config.EnvGroqModel, groq.DefaultModel)

			// Create Groq client
			groqClient := groq.NewClient(groqAPIKey, groqModel, logger)

			// Create service
			service, err := ai_finding_enricher.NewService(redisClient, groqClient, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to create service: %w", err)
			}

			// Create and return consumer
			return ai_finding_enricher.NewConsumer(redisClient, service, logger), nil
		},
	})
}

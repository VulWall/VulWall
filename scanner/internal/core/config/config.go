package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	RedisURI     string
	MongoURI     string
	MongoDB      string
	ServiceName  string
	Environment  string
	ShodanAPIKey string
}

func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	return &Config{
		RedisURI:     getEnv("REDIS_URI", "redis://localhost:6379/0"),
		MongoURI:     getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:      getEnv("MONGO_DB", "VulWall-Dev"),
		ServiceName:  getEnv("SERVICE_NAME", "vulwall-scanner"),
		Environment:  getEnv("ENVIRONMENT", "development"),
		ShodanAPIKey: getEnv("SHODAN_API_KEY", ""),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

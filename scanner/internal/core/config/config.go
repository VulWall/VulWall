package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	MongoURI      string
	MongoDB       string
	ServiceName   string
	Environment   string
	ShodanAPIKey  string
}

func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))

	return &Config{
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       redisDB,
		MongoURI:      getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:       getEnv("MONGO_DB", "VulWall-Dev"),
		ServiceName:   getEnv("SERVICE_NAME", "vulwall-scanner"),
		Environment:   getEnv("ENVIRONMENT", "development"),
		ShodanAPIKey:  getEnv("SHODAN_API_KEY", ""),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

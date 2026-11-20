package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds universal settings needed by all services.
// Service-specific settings should use GetEnv() with constants from env.go.
type Config struct {
	RedisURI    string
	MongoURI    string
	MongoDB     string
	ServiceName string
	Environment string
}

// Load loads universal configuration from environment variables.
// Service-specific settings should use GetEnv() directly.
func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	return &Config{
		RedisURI:    GetEnv(EnvRedisURI, "redis://localhost:6379/0"),
		MongoURI:    GetEnv(EnvMongoURI, "mongodb://localhost:27017"),
		MongoDB:     GetEnv(EnvMongoDB, "vulwall"),
		ServiceName: GetEnv(EnvServiceName, "vulwall-scanner"),
		Environment: GetEnv(EnvEnvironment, "development"),
	}, nil
}

// GetEnv returns the value of an environment variable or a default value.
// Use with constants from env.go for compile-time safety.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvBool returns a boolean environment variable or a default value.
// Accepts: true/1/yes/on for true, false/0/no/off for false.
func GetEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	// Check for common true values
	if value == "true" || value == "1" || value == "yes" || value == "on" {
		return true
	}
	// Check for common false values
	if value == "false" || value == "0" || value == "no" || value == "off" {
		return false
	}
	return defaultValue
}

// GetEnvInt returns an integer environment variable or a default value.
func GetEnvInt(key string, defaultValue int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultValue
}

// GetEnvInt64 returns an int64 environment variable or a default value.
func GetEnvInt64(key string, defaultValue int64) int64 {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

// GetEnvFloat64 returns a float64 environment variable or a default value.
func GetEnvFloat64(key string, defaultValue float64) float64 {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return defaultValue
}

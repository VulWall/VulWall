package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	RedisURI           string
	MongoURI           string
	MongoDB            string
	ServiceName        string
	Environment        string
	ShodanAPIKey       string
	IPEnrichmentDBPath string
	WAFRulesPath       string
}

func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	return &Config{
		RedisURI:           getEnv("REDIS_URI", "redis://localhost:6379/0"),
		MongoURI:           getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:            getEnv("MONGO_DB", "VulWall-Dev"),
		ServiceName:        getEnv("SERVICE_NAME", "vulwall-scanner"),
		Environment:        getEnv("DOPPLER_ENVIRONMENT", "development"),
		ShodanAPIKey:       getEnv("SHODAN_API_KEY", ""),
		IPEnrichmentDBPath: getEnv("IP_ENRICHMENT_DB_PATH", ""),
		WAFRulesPath:       getEnv("WAF_RULES_PATH", "./internal/active_recon/waf_detector/patterns/waf_rules.json"),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

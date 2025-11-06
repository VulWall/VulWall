package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	RedisURI             string
	MongoURI             string
	MongoDB              string
	ServiceName          string
	Environment          string
	ShodanAPIKey         string
	IPEnrichmentDBPath   string
	WAFRulesPath         string
	CloudDetectorEnabled bool
	CloudDataDir         string
}

func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	return &Config{
		RedisURI:             getEnv("REDIS_URI", "redis://localhost:6379/0"),
		MongoURI:             getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:              getEnv("MONGO_DB", "VulWall-Dev"),
		ServiceName:          getEnv("SERVICE_NAME", "vulwall-scanner"),
		Environment:          getEnv("DOPPLER_ENVIRONMENT", "development"),
		ShodanAPIKey:         getEnv("SHODAN_API_KEY", ""),
		IPEnrichmentDBPath:   getEnv("IP_ENRICHMENT_DB_PATH", "./data/dbip-isp-country.mmdb"),
		WAFRulesPath:         getEnv("WAF_RULES_PATH", "./internal/active_recon/discovery_enrichment/waf/patterns/waf_rules.json"),
		CloudDetectorEnabled: getEnvBool("CLOUD_DETECTOR_ENABLED", true),
		CloudDataDir:         getEnv("CLOUD_DATA_DIR", "./internal/active_recon/discovery_enrichment/cloud/data"),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
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

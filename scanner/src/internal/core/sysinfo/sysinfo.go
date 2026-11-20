// Package sysinfo publishes the scanner's version and the versions of the
// tools and data it runs with to the system_info collection, so the web app
// can show them in its About dialog. It is not scan data: only this package
// writes the "scanner" document.
package sysinfo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/oschwald/maxminddb-golang"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const (
	// Collection holds one document per component; the scanner owns DocID.
	Collection = "system_info"
	DocID      = "scanner"

	// RefreshInterval is how often the document is re-collected. Templates
	// update at runtime (first boot and NUCLEI_TEMPLATE_UPDATE_CRON); the
	// other values only change when the container restarts.
	RefreshInterval = 5 * time.Minute
)

// Info is the system_info document. An empty string means "not known"; the
// web app shows it as unknown.
type Info struct {
	Version                  string     `bson:"version"`
	Nuclei                   string     `bson:"nuclei"`
	NucleiTemplates          string     `bson:"nuclei_templates"`
	NucleiTemplatesUpdatedAt *time.Time `bson:"nuclei_templates_updated_at"`
	TestSSL                  string     `bson:"testssl"`
	Retire                   string     `bson:"retire"`
	DBIPCountryDate          string     `bson:"dbip_country_date"`
	DBIPASNDate              string     `bson:"dbip_asn_date"`
	StartedAt                time.Time  `bson:"started_at"`
	UpdatedAt                time.Time  `bson:"updated_at"`
}

// Sources says where Collect reads each value.
type Sources struct {
	// NucleiTemplatesConfig is nuclei's .templates-config.json. nuclei writes
	// it after each template update; it is missing before the first one.
	NucleiTemplatesConfig string
	// RetirePackageJSON is the package.json of the installed retire module.
	// Read at runtime because Dependabot bumps retire through the lockfile.
	RetirePackageJSON string
	CountryDB         string
	ASNDB             string
}

// DefaultSources returns the paths used in the scanner image.
func DefaultSources() Sources {
	nucleiConfig := ""
	if dir, err := os.UserConfigDir(); err == nil {
		nucleiConfig = filepath.Join(dir, "nuclei", ".templates-config.json")
	}
	return Sources{
		NucleiTemplatesConfig: nucleiConfig,
		RetirePackageJSON:     "/opt/retire/node_modules/retire/package.json",
		CountryDB:             config.GetEnv(config.EnvIPEnrichmentDBPath, "./data/dbip-country-lite.mmdb"),
		ASNDB:                 config.GetEnv(config.EnvIPASNDBPath, "./data/dbip-asn-lite.mmdb"),
	}
}

// Collect reads every value. A value that cannot be read stays empty; it
// never fails.
func Collect(src Sources, startedAt time.Time) Info {
	info := Info{
		// Set in scanner/Dockerfile from the pinned build args.
		Version:   os.Getenv(config.EnvVulWallVersion),
		Nuclei:    os.Getenv(config.EnvNucleiVersion),
		TestSSL:   os.Getenv(config.EnvTestSSLVersion),
		Retire:    jsonString(src.RetirePackageJSON, "version"),
		StartedAt: startedAt.UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	info.NucleiTemplates, info.NucleiTemplatesUpdatedAt = templates(src.NucleiTemplatesConfig)
	info.DBIPCountryDate = mmdbBuildDate(src.CountryDB)
	info.DBIPASNDate = mmdbBuildDate(src.ASNDB)
	return info
}

// templates returns the installed templates version and when the templates
// directory was last written (its .checksum file, rewritten by every update).
func templates(configPath string) (string, *time.Time) {
	var cfg struct {
		Version string `json:"nuclei-templates-version"`
		Dir     string `json:"nuclei-templates-directory"`
	}
	if !readJSON(configPath, &cfg) {
		return "", nil
	}
	if cfg.Dir == "" {
		return cfg.Version, nil
	}
	st, err := os.Stat(filepath.Join(cfg.Dir, ".checksum"))
	if err != nil {
		return cfg.Version, nil
	}
	t := st.ModTime().UTC()
	return cfg.Version, &t
}

// mmdbBuildDate returns the database build date (YYYY-MM-DD) from the MMDB
// metadata, or "" when the file is missing or unreadable.
func mmdbBuildDate(path string) string {
	if path == "" {
		return ""
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return ""
	}
	defer db.Close()
	if db.Metadata.BuildEpoch == 0 {
		return ""
	}
	return time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC().Format("2006-01-02")
}

func jsonString(path, key string) string {
	var m map[string]any
	if !readJSON(path, &m) {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func readJSON(path string, v any) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

// Publish upserts the scanner document.
func Publish(ctx context.Context, db *mongo.Database, info Info) error {
	_, err := db.Collection(Collection).UpdateOne(ctx,
		bson.M{"_id": DocID},
		bson.M{"$set": info},
		options.Update().SetUpsert(true))
	return err
}

// Run publishes at once and then every RefreshInterval until ctx ends. A
// failed write is logged, never returned: the About dialog is not worth
// stopping the scanner for.
func Run(ctx context.Context, db *mongo.Database, src Sources, log *zap.Logger) error {
	startedAt := time.Now()
	ticker := time.NewTicker(RefreshInterval)
	defer ticker.Stop()
	for {
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := Publish(writeCtx, db, Collect(src, startedAt)); err != nil && ctx.Err() == nil {
			log.Warn("Could not write system info", zap.Error(err))
		}
		cancel()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

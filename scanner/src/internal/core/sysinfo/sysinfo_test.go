package sysinfo

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCollectReadsEnvAndFiles(t *testing.T) {
	dir := t.TempDir()
	templatesDir := filepath.Join(dir, "templates")
	if err := os.Mkdir(templatesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(templatesDir, ".checksum"), "x")
	nucleiConfig := filepath.Join(dir, ".templates-config.json")
	writeFile(t, nucleiConfig, `{"nuclei-templates-directory":"`+templatesDir+`","nuclei-templates-version":"v10.5.2"}`)
	retire := filepath.Join(dir, "package.json")
	writeFile(t, retire, `{"name":"retire","version":"5.4.2"}`)

	t.Setenv("VULWALL_VERSION", "v1.2.3")
	t.Setenv("NUCLEI_VERSION", "3.11.1")
	t.Setenv("TESTSSL_VERSION", "v3.2.5")

	started := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	info := Collect(Sources{NucleiTemplatesConfig: nucleiConfig, RetirePackageJSON: retire}, started)

	if info.Version != "v1.2.3" || info.Nuclei != "3.11.1" || info.TestSSL != "v3.2.5" {
		t.Errorf("env values = %q %q %q", info.Version, info.Nuclei, info.TestSSL)
	}
	if info.Retire != "5.4.2" {
		t.Errorf("Retire = %q", info.Retire)
	}
	if info.NucleiTemplates != "v10.5.2" {
		t.Errorf("NucleiTemplates = %q", info.NucleiTemplates)
	}
	if info.NucleiTemplatesUpdatedAt == nil {
		t.Error("NucleiTemplatesUpdatedAt is nil, want the .checksum mtime")
	}
	if !info.StartedAt.Equal(started) {
		t.Errorf("StartedAt = %v", info.StartedAt)
	}
}

func TestCollectMissingSourcesStayEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VULWALL_VERSION", "")
	t.Setenv("NUCLEI_VERSION", "")
	t.Setenv("TESTSSL_VERSION", "")
	notJSON := filepath.Join(dir, "broken.json")
	writeFile(t, notJSON, "{not json")

	info := Collect(Sources{
		NucleiTemplatesConfig: filepath.Join(dir, "missing.json"),
		RetirePackageJSON:     notJSON,
		CountryDB:             filepath.Join(dir, "missing.mmdb"),
		ASNDB:                 notJSON, // not an MMDB file
	}, time.Now())

	for name, v := range map[string]string{
		"Version": info.Version, "Nuclei": info.Nuclei, "TestSSL": info.TestSSL, "Retire": info.Retire,
		"NucleiTemplates": info.NucleiTemplates, "DBIPCountryDate": info.DBIPCountryDate, "DBIPASNDate": info.DBIPASNDate,
	} {
		if v != "" {
			t.Errorf("%s = %q, want empty", name, v)
		}
	}
	if info.NucleiTemplatesUpdatedAt != nil {
		t.Errorf("NucleiTemplatesUpdatedAt = %v, want nil", info.NucleiTemplatesUpdatedAt)
	}
}

// TestPublishUpsertsAgainstMongo checks the upsert against a real MongoDB.
// Set VULWALL_TEST_MONGO_URI to run it.
func TestPublishUpsertsAgainstMongo(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_MONGO_URI not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("sysinfo_test_" + strconv.FormatInt(time.Now().UnixNano(), 36))
	defer db.Drop(ctx)

	if err := Publish(ctx, db, Info{Version: "v1.0.0", Nuclei: "3.11.1"}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(ctx, db, Info{Version: "v1.0.1", Nuclei: "3.11.1"}); err != nil {
		t.Fatal(err)
	}

	n, err := db.Collection(Collection).CountDocuments(ctx, bson.M{})
	if err != nil || n != 1 {
		t.Fatalf("count = %d, err = %v; want one document", n, err)
	}
	var got bson.M
	if err := db.Collection(Collection).FindOne(ctx, bson.M{"_id": DocID}).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != "v1.0.1" {
		t.Errorf("version = %v, want v1.0.1", got["version"])
	}
}

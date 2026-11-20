package geolocation

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnrichWithDBIPLite runs against real DB-IP Lite files when
// VULWALL_TEST_MMDB_DIR names a directory that holds country.mmdb and asn.mmdb
// (download from https://db-ip.com/db/lite.php). Skipped otherwise.
func TestEnrichWithDBIPLite(t *testing.T) {
	dir := os.Getenv("VULWALL_TEST_MMDB_DIR")
	if dir == "" {
		t.Skip("VULWALL_TEST_MMDB_DIR not set")
	}
	e, err := NewIPEnricher(filepath.Join(dir, "country.mmdb"), filepath.Join(dir, "asn.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	info, err := e.Enrich("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if info.Continent != "NA" || info.Country != "US" || info.ISP != "Google LLC" {
		t.Fatalf("info = %+v, want NA/US/Google LLC", info)
	}
}

func TestMissingCountryDBIsAnError(t *testing.T) {
	if _, err := NewIPEnricher(filepath.Join(t.TempDir(), "missing.mmdb"), ""); err == nil {
		t.Fatal("err = nil, want file-not-found error")
	}
}

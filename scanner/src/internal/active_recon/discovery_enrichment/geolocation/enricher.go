package geolocation

import (
	"fmt"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

// IPInfo contains geolocation information for an IP address
type IPInfo struct {
	Continent string
	Country   string
	ISP       string
}

// IPEnricher provides IP geolocation enrichment from MaxMind DB (MMDB) files.
//
// It reads a country database in the GeoIP2-Country layout (continent.code,
// country.iso_code), such as DB-IP "IP to Country Lite", and an optional ASN
// database in the GeoLite2-ASN layout (autonomous_system_organization), such
// as DB-IP "IP to ASN Lite". The ASN organization fills the ISP field. When no
// ASN database is given, ISP comes from traits.isp in the country database
// (present in commercial ISP editions) or is "Unknown".
type IPEnricher struct {
	countryDB *maxminddb.Reader
	asnDB     *maxminddb.Reader
}

// NewIPEnricher opens the country database at countryPath and, if asnPath is
// not empty, the ASN database. A missing or unreadable ASN database is not an
// error: ISP lookups then fall back as described on IPEnricher.
func NewIPEnricher(countryPath, asnPath string) (*IPEnricher, error) {
	countryDB, err := openMMDB(countryPath)
	if err != nil {
		return nil, err
	}
	e := &IPEnricher{countryDB: countryDB}
	if asnPath != "" {
		if asnDB, err := openMMDB(asnPath); err == nil {
			e.asnDB = asnDB
		}
	}
	return e, nil
}

// HasASN reports whether an ASN database is loaded.
func (e *IPEnricher) HasASN() bool {
	return e.asnDB != nil
}

func openMMDB(path string) (*maxminddb.Reader, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("MMDB database file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to access MMDB database file: %w", err)
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open MMDB database %s: %w", path, err)
	}
	return db, nil
}

// Enrich performs IP geolocation lookup and returns country and ISP information
func (e *IPEnricher) Enrich(ipStr string) (*IPInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	var record struct {
		Continent struct {
			Code string `maxminddb:"code"`
		} `maxminddb:"continent"`
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Traits struct {
			ISP string `maxminddb:"isp"`
		} `maxminddb:"traits"`
	}
	if err := e.countryDB.Lookup(ip, &record); err != nil {
		return nil, fmt.Errorf("database lookup failed: %w", err)
	}

	isp := record.Traits.ISP
	if e.asnDB != nil {
		var asn struct {
			Organization string `maxminddb:"autonomous_system_organization"`
		}
		if err := e.asnDB.Lookup(ip, &asn); err == nil && asn.Organization != "" {
			isp = asn.Organization
		}
	}

	return &IPInfo{
		Continent: orUnknown(record.Continent.Code),
		Country:   orUnknown(record.Country.ISOCode),
		ISP:       orUnknown(isp),
	}, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

// Close closes the MMDB database readers
func (e *IPEnricher) Close() error {
	var err error
	if e.countryDB != nil {
		err = e.countryDB.Close()
	}
	if e.asnDB != nil {
		if asnErr := e.asnDB.Close(); err == nil {
			err = asnErr
		}
	}
	return err
}

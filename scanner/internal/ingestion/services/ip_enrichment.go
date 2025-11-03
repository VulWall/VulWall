package services

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

// IPEnricher provides IP geolocation enrichment using MaxMind DB format
type IPEnricher struct {
	db *maxminddb.Reader
}

// NewIPEnricher creates a new IP enricher with the specified MMDB database path
func NewIPEnricher(dbPath string) (*IPEnricher, error) {
	// Check if file exists
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("MMDB database file not found: %s", dbPath)
		}
		return nil, fmt.Errorf("failed to access MMDB database file: %w", err)
	}

	// Open the database
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open MMDB database: %w", err)
	}

	return &IPEnricher{db: db}, nil
}

// Enrich performs IP geolocation lookup and returns country and ISP information
func (e *IPEnricher) Enrich(ipStr string) (*IPInfo, error) {
	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// MMDB format structure (GeoIP2/GeoLite2 format)
	// Actual structure from the database file
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

	// Lookup IP in database
	err := e.db.Lookup(ip, &record)
	if err != nil {
		return nil, fmt.Errorf("database lookup failed: %w", err)
	}

	// Extract continent code
	continent := record.Continent.Code
	if continent == "" {
		continent = "Unknown"
	}

	// Extract country code
	country := record.Country.ISOCode
	if country == "" {
		country = "Unknown"
	}

	// Extract ISP
	isp := record.Traits.ISP
	if isp == "" {
		isp = "Unknown"
	}

	return &IPInfo{
		Continent: continent,
		Country:   country,
		ISP:       isp,
	}, nil
}

// Close closes the MMDB database reader
func (e *IPEnricher) Close() error {
	if e.db != nil {
		return e.db.Close()
	}
	return nil
}

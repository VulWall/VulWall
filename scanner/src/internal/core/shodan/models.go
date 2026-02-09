package shodan

// DNSDomainResponse represents Shodan DNS domain API response
type DNSDomainResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

// HostInfo represents Shodan /shodan/host/{ip} response
type HostInfo struct {
	IP          string     `json:"ip_str"`
	Ports       []int      `json:"ports"`
	CountryCode string     `json:"country_code,omitempty"`
	CountryName string     `json:"country_name,omitempty"`
	City        string     `json:"city,omitempty"`
	ISP         string     `json:"isp,omitempty"`
	Org         string     `json:"org,omitempty"`
	ASN         string     `json:"asn,omitempty"`
	Hostnames   []string   `json:"hostnames,omitempty"`
	Data        []PortData `json:"data,omitempty"`
}

// PortData represents service data for a single port
type PortData struct {
	Port      int     `json:"port"`
	Transport string  `json:"transport,omitempty"` // tcp, udp
	Product   string  `json:"product,omitempty"`
	Version   string  `json:"version,omitempty"`
	Banner    string  `json:"data,omitempty"` // Raw banner data
	HTTP      *HTTPInfo `json:"http,omitempty"`
	SSL       *SSLInfo  `json:"ssl,omitempty"`
}

// HTTPInfo represents HTTP module data
type HTTPInfo struct {
	Server     string `json:"server,omitempty"`
	Title      string `json:"title,omitempty"`
	StatusCode int    `json:"status,omitempty"`
}

// SSLInfo represents SSL module data
type SSLInfo struct {
	CertSubject string            `json:"cert_subject,omitempty"`
	CertIssuer  string            `json:"cert_issuer,omitempty"`
	Cert        *SSLCertInfo      `json:"cert,omitempty"`
	Versions    []string          `json:"versions,omitempty"`
}

// SSLCertInfo represents SSL certificate information
type SSLCertInfo struct {
	Subject     map[string]string `json:"subject,omitempty"`
	Issuer      map[string]string `json:"issuer,omitempty"`
	Expired     bool              `json:"expired,omitempty"`
	Expires     string            `json:"expires,omitempty"`
	Fingerprint map[string]string `json:"fingerprint,omitempty"`
}

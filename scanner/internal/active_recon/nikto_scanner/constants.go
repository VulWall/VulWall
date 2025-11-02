package nikto_scanner

const (
	// Consumer group for Nikto scanner service
	// Listens to both domain_discovery_results and ip_discovery_results
	GroupNiktoScanner = "nikto_scanner_service"
)

// TuningCategories maps Nikto tuning codes to readable category names
var TuningCategories = map[string]string{
	"0": "file-upload",
	"1": "interesting-file",
	"2": "misconfiguration",
	"3": "info-disclosure",
	"4": "injection",
	"5": "remote-file-retrieval",
	"6": "denial-of-service",
	"7": "remote-file-retrieval",
	"8": "command-execution",
	"9": "sql-injection",
	"a": "authentication-bypass",
	"b": "software-identification",
	"c": "remote-source-inclusion",
	"d": "websocket",
	"e": "administrative-console",
	"x": "reverse-tuning",
}

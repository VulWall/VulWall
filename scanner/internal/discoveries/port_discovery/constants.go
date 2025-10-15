package port_discovery

const (
	// Port discovery service consumer group
	// Input stream: shared.StreamIPDiscoveryQueue
	// Output stream: shared.StreamIPDiscoveryResults
	GroupPortDiscovery = "port_discovery_service"
)

// CommonPorts defines the most commonly scanned ports
var CommonPorts = []int{
	20,    // FTP Data
	21,    // FTP Control
	22,    // SSH
	23,    // Telnet
	25,    // SMTP
	53,    // DNS
	80,    // HTTP
	110,   // POP3
	143,   // IMAP
	443,   // HTTPS
	465,   // SMTPS
	587,   // SMTP (submission)
	993,   // IMAPS
	995,   // POP3S
	3306,  // MySQL
	3389,  // RDP
	5432,  // PostgreSQL
	5900,  // VNC
	6379,  // Redis
	8080,  // HTTP Alt
	8443,  // HTTPS Alt
	27017, // MongoDB
	27018, // MongoDB shard
}

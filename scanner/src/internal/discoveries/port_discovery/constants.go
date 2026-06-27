package port_discovery

const (
	// Port discovery service consumer group
	// Input stream: shared.StreamIPDiscoveryQueue
	// Output stream: shared.StreamIPDiscoveryResults
	GroupPortDiscovery = "port_discovery_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because port scanning involves multiple connections
	ConsumerBatchSize = 1
)

// CommonPorts defines security-focused ports for external attack surface scanning.
var CommonPorts = []int{
	// File Transfer
	20, 21, // FTP
	873, // rsync

	// Remote Access
	22, 2222, // SSH / SSH alt
	23,       // Telnet
	3389,     // RDP
	5900, 5901, // VNC
	5985, 5986, // WinRM HTTP/HTTPS
	47001, // WinRM alt

	// Email
	25, 465, 587, // SMTP / SMTPS / Submission
	110, 995,     // POP3 / POP3S
	143, 993,     // IMAP / IMAPS

	// DNS
	53,

	// Web / HTTP
	80, 8000, 8008, 8080, 8081, 8090, // HTTP variants
	443, 8443, // HTTPS variants
	3000,  // Grafana / Node.js dev
	5000,  // Flask / dev / Docker Registry
	8888,  // Jupyter / HTTP alt
	9000,  // SonarQube / MinIO
	9090,  // Prometheus
	10000, // Webmin

	// Network Services
	111,      // RPC portmapper
	135, 139, // MS-RPC / NetBIOS
	389, 636, // LDAP / LDAPS
	445,      // SMB
	2049,     // NFS

	// Databases
	1433,       // MSSQL
	1521,       // Oracle
	3306,       // MySQL
	5432,       // PostgreSQL
	5984,       // CouchDB
	6379,       // Redis
	7474, 7687, // Neo4j HTTP / Bolt
	8086,       // InfluxDB
	8091, 8093, // Couchbase admin / query
	9042,       // Cassandra CQL
	9200, 9300, // Elasticsearch HTTP / transport
	11211,      // Memcached
	27017, 27018, // MongoDB / MongoDB shard
	28015, // RethinkDB

	// Admin / Monitoring Panels
	4040,  // Spark UI
	4848,  // GlassFish admin
	5601,  // Kibana
	7001,  // WebLogic
	8161,  // ActiveMQ web console
	8500,  // Consul HTTP API
	8983,  // Solr admin
	15672, // RabbitMQ management UI

	// Message Queues
	2181,  // Zookeeper
	5672,  // RabbitMQ AMQP
	9092,  // Kafka broker
	61616, // ActiveMQ broker

	// Container / Kubernetes
	2375, 2376, // Docker API (unauth / TLS) — unauthenticated = critical finding
	2379, 2380, // etcd client / peer
	6443,       // Kubernetes API server
	10250, 10255, // Kubernetes kubelet / read-only
}

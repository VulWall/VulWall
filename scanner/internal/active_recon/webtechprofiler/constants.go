package webtechprofiler

const (
	// GroupWebTechProfiler is the consumer group name for the WebTechProfiler service
	// Listens to both domain_discovery_results and ip_discovery_results
	GroupWebTechProfiler = "webtechprofiler_service"
)

// WebPorts defines the list of common web service ports to scan
var WebPorts = []int{80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9000}

// isWebPort checks if the given port is a web service port
func isWebPort(port int) bool {
	for _, p := range WebPorts {
		if p == port {
			return true
		}
	}
	return false
}

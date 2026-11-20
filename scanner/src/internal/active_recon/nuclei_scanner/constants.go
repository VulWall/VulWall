package nuclei_scanner

import "time"

const (
	// findingSource is the source of every nuclei finding and coverage record.
	findingSource = "nuclei"

	// Consumer group for Nuclei scanner service
	// Listens to both domain_discovery_results and ip_discovery_results
	GroupNucleiScanner = "nuclei_scanner_service"

	// TemplateUpdateLockKey is the Redis key for the distributed lock that ensures
	// only one replica runs nuclei -update-templates per tick (all replicas share
	// the same templates volume).
	TemplateUpdateLockKey = "nuclei:template-update-lock"

	// TemplateUpdateLockTTL bounds how long the lock is held. Must exceed the 5m
	// update timeout in updateTemplates so the holder never has its lock expire
	// mid-update (which would let ReleaseLock free a lock it no longer owns).
	TemplateUpdateLockTTL = 10 * time.Minute

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because Nuclei scans are slow
	ConsumerBatchSize = 1

	// DefaultWorkers is how many nuclei processes run at the same time across
	// both trigger streams. Override with NUCLEI_WORKERS.
	DefaultWorkers = 2

	// DefaultTemplateUpdateCron is the default cron schedule for template updates
	// Default: 2:00 AM UTC daily ("0 2 * * *")
	// Can be overridden with NUCLEI_TEMPLATE_UPDATE_CRON environment variable
	DefaultTemplateUpdateCron = "0 2 * * *"

	// DefaultIncludeTags are the Nuclei template tags to run by default.
	// Focuses on proven vulnerability classes relevant to external attack surface.
	DefaultIncludeTags = "cve,vuln,exposure,misconfig,default-login,token,takeover,kev,xss,lfi,ssrf,rce,sqli,auth-bypass,unauth,panel"

	// DefaultExcludeTags are the Nuclei template tags to exclude by default.
	// Prevents intrusive/destructive templates from running against production targets.
	DefaultExcludeTags = "intrusive,dos,fuzz"
)

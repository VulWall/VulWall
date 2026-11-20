package shared

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// Coverage statuses (ScanCoverage.Status).
const (
	// CoverageOK: the check ran to completion for the target. For a scanner, Reported lists
	// every finding it reported, so an open finding of that scanner on that target that is
	// not in Reported is no longer present.
	CoverageOK = "ok"
	// CoverageError: the check did not complete. No finding of that source on that target
	// is resolved by the scan.
	CoverageError = "error"
	// CoverageAbsent: domain discovery confirmed that a name it saw before no longer exists
	// (NXDOMAIN or no address, from the local and the public resolvers).
	CoverageAbsent = "absent"
)

// Coverage sources that are not finding sources: domain discovery reports names that are
// gone (CoverageAbsent), port discovery reports an IP whose port scan completed (CoverageOK).
const (
	CoverageSourceDomainDiscovery = "domain_discovery"
	CoverageSourcePortDiscovery   = "port_discovery"
)

// ScanCoverage is positive evidence about one target in one scan: that a check ran to
// completion (or did not), or that a host is gone. It travels on the security_findings
// stream inside a SecurityFinding envelope (SecurityFinding.Coverage), so the scan cannot
// read as drained before ingestion has stored it in scan_coverage. A scan resolves a finding
// only on this evidence, never because data is missing.
type ScanCoverage struct {
	Source      string       `json:"source"`           // the finding source (nuclei, testssl, ...) or CoverageSource*
	DiscoveryID string       `json:"discovery_id"`     // the target; findings reference the same id
	Target      string       `json:"target,omitempty"` // what was checked, for people reading the record
	Status      string       `json:"status"`           // Coverage*
	Error       string       `json:"error,omitempty"`  // why the check did not complete
	Reported    []FindingKey `json:"reported,omitempty"`
}

// FindingKey identifies a finding on a target: ingestion deduplicates findings by
// (org_id, discovery_id, finding_type, title).
type FindingKey struct {
	FindingType string `json:"finding_type" bson:"finding_type"`
	Title       string `json:"title" bson:"title"`
}

// CoverageMessage wraps cov in the SecurityFinding envelope published to security_findings.
func CoverageMessage(orgID string, scanID *string, traceID string, cov ScanCoverage) SecurityFinding {
	return SecurityFinding{
		TraceID:     traceID,
		ScanID:      scanID,
		OrgID:       orgID,
		Source:      cov.Source,
		DiscoveryID: cov.DiscoveryID,
		Timestamp:   time.Now(),
		Coverage:    &cov,
	}
}

// TargetCoverage is the coverage message of a scanner for one scan target: ok with the
// findings it reported, or error when runErr is set. A target whose host did not resolve in
// the scan (ScanTarget.Unresolved) is always an error: a network check of it proves nothing.
func TargetCoverage(source string, target ScanTarget, reported []FindingKey, runErr error) SecurityFinding {
	if runErr == nil && target.Unresolved {
		runErr = errors.New("host did not resolve in this scan")
	}
	cov := ScanCoverage{
		Source:      source,
		DiscoveryID: target.DiscoveryID,
		Target:      target.Target,
		Status:      CoverageOK,
		Reported:    reported,
	}
	if runErr != nil {
		cov.Status, cov.Error, cov.Reported = CoverageError, runErr.Error(), nil
	}
	return CoverageMessage(target.OrgID, target.ScanID, target.TraceID, cov)
}

// IsConnRefused reports whether err is a refused TCP connection: a definite answer that
// nothing listens on the port, unlike a timeout.
func IsConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// ErrGone marks a probe error that is a definite answer that the resource does not exist
// (HTTP 404 or 410), not a failure to look.
var ErrGone = errors.New("resource does not exist")

// ErrNoAnswer marks a check over several probes in which no probe got an HTTP answer: every
// connection was refused, so there was nothing to check.
var ErrNoAnswer = errors.New("no protocol answered")

// ProbeError returns what makes a check over several probes (http and https) incomplete:
// the probe errors other than a refused connection or ErrGone, joined; or ErrNoAnswer when
// no probe got an answer (every one was refused); or nil. A refused probe is a definite
// answer (nothing listens), so one refused protocol next to one that answered does not make
// the check incomplete; a timeout, a TLS failure or a blocked response (403, 429, 5xx, a WAF
// challenge: see BlockedResponse) does, because it hides what the probe would have found.
func ProbeError(errs ...error) error {
	var incomplete []error
	answered := false
	for _, err := range errs {
		switch {
		case err == nil || errors.Is(err, ErrGone):
			answered = true
		case !IsConnRefused(err):
			incomplete = append(incomplete, err)
		}
	}
	if len(incomplete) > 0 {
		return errors.Join(incomplete...)
	}
	if !answered {
		return fmt.Errorf("%w: every connection was refused", ErrNoAnswer)
	}
	return nil
}

// reachTimeout bounds one connection attempt of Reachable.
const reachTimeout = 5 * time.Second

// Reachable returns nil when a TCP connection to any of addrs (host:port) succeeds, else the
// joined dial errors. Scanners whose tool reports "no findings" also when the target stopped
// answering (nuclei) call it after the run: without it, a host that went down or banned the
// scanner mid-run would read as "checked, nothing found". It dials through the SSRF guard.
func Reachable(ctx context.Context, addrs ...string) error {
	dial := SSRFSafeDialContext(&net.Dialer{Timeout: reachTimeout})
	var errs []error
	for _, addr := range addrs {
		conn, err := dial(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return errors.New("no address to check")
	}
	return errors.Join(errs...)
}

// FindingMetaScanHost is the findings.metadata key that names the host of a nuclei
// <name>:<port> run on a CDN edge port. Finding resolution never resolves such a finding as
// not_reproduced: that run reports no coverage (see nuclei_scanner.ProcessCDNPort).
const FindingMetaScanHost = "scan_host"

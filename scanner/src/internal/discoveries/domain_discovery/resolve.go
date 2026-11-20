package domain_discovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.uber.org/zap"
)

// defaultDNSResolveConcurrency is the number of subdomain lookups that run at once when
// DNS_RESOLVE_CONCURRENCY is not set.
const defaultDNSResolveConcurrency = 50

// A discovery whose lookups failed this much is degraded: its scan did not see the names it
// could not resolve, so it must not resolve their findings. Some failures are normal noise
// (passive sources return names with broken delegations), hence the floor on the name count.
const (
	dnsDegradedMinNames       = 50 // more than this many names, and
	dnsDegradedFailurePercent = 20 // more than this percent of them failed
)

// subdomainLookupsDegraded reports whether more than dnsDegradedFailurePercent of more than
// dnsDegradedMinNames subdomain lookups failed (isLookupFailure).
func subdomainLookupsDegraded(names, failures int) bool {
	return names > dnsDegradedMinNames && failures*100 > names*dnsDegradedFailurePercent
}

// degradedReason picks the one reason a domain discovery reports for its root asset, or ""
// when the discovery saw the whole attack surface. One reason per job keeps the signal
// idempotent; the root's own problem comes first because it is what the user must fix.
func degradedReason(rootReason string, enumFailed bool, names, failures int) string {
	switch {
	case rootReason != "":
		return rootReason
	case enumFailed:
		return shared.ScanDegradedSubdomainEnumFailed
	case subdomainLookupsDegraded(names, failures):
		return shared.ScanDegradedDNSFailures
	}
	return ""
}

// isLookupFailure reports whether a lookup error means the resolver could not answer
// (timeout, SERVFAIL, REFUSED, network error), as opposed to a clean answer that the name
// does not exist or has no address. Only the former hides a name that may still be live.
func isLookupFailure(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false
	}
	return true
}

// lookupFunc returns every A and AAAA answer for host.
type lookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// resolvePublic resolves names with at most workers lookups at a time. For each name whose
// answers are all public (selectPublicIP, so ALLOW_PRIVATE_TARGETS applies), it calls found
// with the name and the address to record. found runs on the worker goroutines, so it must be
// safe for concurrent use; it is called as soon as a name resolves, which keeps the
// downstream stages busy while the rest of the names resolve.
//
// A name that does not resolve or has a private answer is skipped and logged; it does not
// stop the others. resolvePublic returns the number of lookups that failed (isLookupFailure)
// rather than finding the name absent. It returns only after every call to found has
// returned, so a caller that ACKs its job after resolvePublic returns ACKs after the last
// publish. It returns ctx.Err() when the context was cancelled: the result is then incomplete.
func resolvePublic(ctx context.Context, names []string, workers int, lookup lookupFunc, found func(host, ip string), log *zap.Logger) (failures int, err error) {
	if workers < 1 {
		workers = 1
	}

	work := make(chan string)
	var failed atomic.Int64
	var wg sync.WaitGroup
	for range min(workers, len(names)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range work {
				ips, err := lookup(ctx, name)
				if err != nil {
					if isLookupFailure(err) {
						failed.Add(1)
					}
					log.Debug("Skipping subdomain: DNS resolution failed",
						zap.String("subdomain", name), zap.Error(err))
					continue
				}
				ip, err := selectPublicIP(ips)
				if err != nil {
					log.Warn("Skipping subdomain: resolves to private IP",
						zap.String("subdomain", name), zap.Error(err))
					continue
				}
				found(name, ip)
			}
		}()
	}

feed:
	for _, name := range names {
		select {
		case work <- name:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()

	// Lookups cut off by cancellation were skipped as failures, so a cancelled run is
	// incomplete even when every name was handed out.
	return int(failed.Load()), ctx.Err()
}

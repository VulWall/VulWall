package domain_discovery

import (
	"context"
	"net"
	"sync"

	"go.uber.org/zap"
)

// defaultDNSResolveConcurrency is the number of subdomain lookups that run at once when
// DNS_RESOLVE_CONCURRENCY is not set.
const defaultDNSResolveConcurrency = 50

// lookupFunc returns every A and AAAA answer for host.
type lookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// resolvePublic resolves names with at most workers lookups at a time. For each name whose
// answers are all public (selectPublicIP, so ALLOW_PRIVATE_TARGETS applies), it calls found
// with the name and the address to record. found runs on the worker goroutines, so it must be
// safe for concurrent use; it is called as soon as a name resolves, which keeps the
// downstream stages busy while the rest of the names resolve.
//
// A name that does not resolve or has a private answer is skipped and logged; it does not
// stop the others. resolvePublic returns only after every call to found has returned, so a
// caller that ACKs its job after resolvePublic returns ACKs after the last publish. It
// returns ctx.Err() when the context was cancelled: the result is then incomplete.
func resolvePublic(ctx context.Context, names []string, workers int, lookup lookupFunc, found func(host, ip string), log *zap.Logger) error {
	if workers < 1 {
		workers = 1
	}

	work := make(chan string)
	var wg sync.WaitGroup
	for range min(workers, len(names)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range work {
				ips, err := lookup(ctx, name)
				if err != nil {
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
	return ctx.Err()
}

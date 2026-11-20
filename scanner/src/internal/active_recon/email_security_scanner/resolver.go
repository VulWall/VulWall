package email_security_scanner

import (
	"context"
	"fmt"
	"net"
)

// dnsResolver is the part of net.Resolver the checks use.
type dnsResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// confirmingResolver asks the public resolvers again when the local one says a name has no
// record. Under Docker's embedded DNS an upstream REFUSED can surface as NXDOMAIN, and a false
// "no record" would both report a missing SPF/DMARC record and resolve the findings of the
// record that is really there. The public answer wins when it has records; when it fails, the
// lookup fails (the check is incomplete). With no public resolvers (DNS_RECHECK_RESOLVERS=off)
// the local answer is final.
type confirmingResolver struct {
	local  dnsResolver
	public dnsResolver // nil: no confirmation
}

func (r confirmingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return confirm(ctx, name, r.local.LookupTXT, r.public, dnsResolver.LookupTXT)
}

func (r confirmingResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return confirm(ctx, name, r.local.LookupMX, r.public, dnsResolver.LookupMX)
}

func (r confirmingResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return confirm(ctx, name, r.local.LookupNS, r.public, dnsResolver.LookupNS)
}

func confirm[T any](ctx context.Context, name string,
	local func(context.Context, string) (T, error),
	public dnsResolver, publicLookup func(dnsResolver, context.Context, string) (T, error)) (T, error) {
	res, err := local(ctx, name)
	if err == nil || !isDNSNotFound(err) || public == nil {
		return res, err
	}
	pres, perr := publicLookup(public, ctx, name)
	switch {
	case perr == nil:
		return pres, nil // the local resolver missed the record
	case isDNSNotFound(perr):
		return res, err // confirmed: no record
	default:
		var zero T
		return zero, fmt.Errorf("%s: local resolver said not found, public resolvers did not confirm: %w", name, perr)
	}
}

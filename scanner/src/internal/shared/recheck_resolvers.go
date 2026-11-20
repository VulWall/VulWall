package shared

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

// defaultRecheckResolvers are asked directly when the local resolver says a name does not
// exist. Under Docker's embedded DNS an upstream REFUSED can surface as NXDOMAIN, so the local
// answer alone cannot tell "the name is gone" from "the resolver failed".
const defaultRecheckResolvers = "1.1.1.1,8.8.8.8"

// RecheckResolvers returns the resolvers of DNS_RECHECK_RESOLVERS as host:port, or nil when
// the value is "off".
func RecheckResolvers() []string {
	v := strings.TrimSpace(config.GetEnv(config.EnvDNSRecheckResolvers, defaultRecheckResolvers))
	if strings.EqualFold(v, "off") {
		return nil
	}
	var servers []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		servers = append(servers, s)
	}
	return servers
}

// RecheckResolver returns a resolver that asks the given servers directly (the first that
// accepts the connection), or nil when there are none.
func RecheckResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var err error
			for _, server := range servers {
				var conn net.Conn
				if conn, err = d.DialContext(ctx, network, server); err == nil {
					return conn, nil
				}
			}
			return nil, err
		},
	}
}

package certificate_scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ScanTarget is the shared scan target. Target is the host:port the check dials.
type ScanTarget = shared.ScanTarget

// thresholds are the day limits of the two severities.
type thresholds struct {
	warn     int // expires within warn days: medium
	critical int // expires within critical days, or expired: high
}

// Service reads the leaf certificate of a TLS target and reports one that expires soon or
// has expired.
type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	limits  thresholds
	now     func() time.Time
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	publish func(ctx context.Context, msg shared.SecurityFinding) error
}

// NewService creates the service with the thresholds from the environment. It dials through
// the SSRF guard (ALLOW_PRIVATE_TARGETS applies).
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	limits, err := loadThresholds()
	if err != nil {
		logger.Warn("Invalid certificate expiry thresholds; using the defaults",
			zap.Error(err),
			zap.Int("warn_days", limits.warn),
			zap.Int("critical_days", limits.critical),
		)
	}
	return &Service{
		logger: logger,
		tracer: otel.Tracer("certificate-scanner"),
		limits: limits,
		now:    time.Now,
		dial:   shared.SSRFSafeDialContext(&net.Dialer{Timeout: handshakeTimeout}),
		publish: func(ctx context.Context, msg shared.SecurityFinding) error {
			msg.TraceContext = telemetry.InjectTraceContext(ctx)
			return redisx.PublishToStream(ctx, redisClient, shared.StreamSecurityFindings, msg, 0)
		},
	}
}

// loadThresholds reads CERT_EXPIRY_WARN_DAYS and CERT_EXPIRY_CRITICAL_DAYS. A value that is
// not a positive integer, or a critical limit above the warn limit, gives both defaults and
// an error that says why.
func loadThresholds() (thresholds, error) {
	defaults := thresholds{warn: DefaultWarnDays, critical: DefaultCriticalDays}
	warn, err := positiveDays(config.EnvCertExpiryWarnDays, DefaultWarnDays)
	if err != nil {
		return defaults, err
	}
	critical, err := positiveDays(config.EnvCertExpiryCriticalDays, DefaultCriticalDays)
	if err != nil {
		return defaults, err
	}
	if critical > warn {
		return defaults, fmt.Errorf("%s (%d) is above %s (%d)",
			config.EnvCertExpiryCriticalDays, critical, config.EnvCertExpiryWarnDays, warn)
	}
	return thresholds{warn: warn, critical: critical}, nil
}

// positiveDays reads env as a positive number of days; unset or empty gives def.
func positiveDays(env string, def int) (int, error) {
	v := strings.TrimSpace(config.GetEnv(env, ""))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return def, fmt.Errorf("%s=%q is not a positive number of days", env, v)
	}
	return n, nil
}

// ProcessTarget checks one target and publishes its finding (if any), then its coverage:
// ok with the finding's key only when the handshake completed and the certificate was read,
// error otherwise. A failed publish is returned (the trigger is retried); a failed check is
// a result, not a handler error.
//
// serverName is the SNI to send: the hostname for a domain target, "" for an IP:port target
// (the server's default certificate).
func (s *Service) ProcessTarget(ctx context.Context, target ScanTarget, serverName string) error {
	ctx, span := s.tracer.Start(ctx, "certificate",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
		),
	)
	defer span.End()

	if target.Unresolved {
		// No address in this scan: a check proves nothing (TargetCoverage reports error).
		return s.publish(ctx, shared.TargetCoverage(findingSource, target, nil, nil))
	}
	var reported []shared.FindingKey
	cert, err := s.readLeaf(ctx, target.Target, serverName)
	if ctx.Err() != nil {
		return ctx.Err() // shutdown: leave the trigger pending
	}
	if err != nil {
		s.logger.Info("Certificate check incomplete; its findings on this target stay open",
			zap.String("target", target.Target), zap.Error(err))
		span.SetAttributes(attribute.Bool("scan.success", false))
	} else if finding, ok := s.evaluate(cert, target); ok {
		if err := s.publish(ctx, finding); err != nil {
			return fmt.Errorf("publish certificate finding for %s: %w", target.Target, err)
		}
		reported = append(reported, shared.FindingKey{FindingType: finding.FindingType, Title: finding.Title})
		span.SetAttributes(attribute.String("finding.type", finding.FindingType))
	}
	return s.publish(ctx, shared.TargetCoverage(findingSource, target, reported, err))
}

// readLeaf dials addr (host:port) and returns the leaf certificate of the TLS handshake. It
// only reads the certificate: the chain is not verified (an expired or self-signed one must
// still be read), and no request is sent.
func (s *Service) readLeaf(ctx context.Context, addr, serverName string) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, err := s.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,             //nolint:gosec // reading the certificate, not trusting the peer
		MinVersion:         tls.VersionTLS10, // a legacy server still has a certificate to read
		CipherSuites:       allCipherSuites,  // also RSA key exchange, which Go no longer offers by default
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("server sent no certificate")
	}
	return certs[0], nil
}

// allCipherSuites is every TLS 1.0-1.2 suite Go implements, insecure ones included: the
// handshake only reads the certificate, so it must succeed with an old server too.
var allCipherSuites = func() []uint16 {
	var ids []uint16
	for _, list := range [][]*tls.CipherSuite{tls.CipherSuites(), tls.InsecureCipherSuites()} {
		for _, cs := range list {
			ids = append(ids, cs.ID)
		}
	}
	return ids
}()

// maxNameLen caps the subject and issuer in the description: the scanned server chooses
// them, and the description also goes to the knowledge-base prompt.
const maxNameLen = 200

// clip returns s cut to maxNameLen bytes, on a rune boundary, with "..." when cut.
func clip(s string) string {
	if len(s) <= maxNameLen {
		return s
	}
	cut := maxNameLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// evaluate returns the finding for cert, and false when it is valid for longer than the warn
// limit.
func (s *Service) evaluate(cert *x509.Certificate, target ScanTarget) (shared.SecurityFinding, bool) {
	now := s.now()
	left := cert.NotAfter.Sub(now)
	day := 24 * time.Hour
	notAfter := cert.NotAfter.UTC().Format("2006-01-02 15:04 UTC")

	var findingType, title, severity, when string
	switch {
	case left <= 0:
		findingType, title, severity = findingTypeExpired, titleExpired+displayHost(target), shared.SeverityHigh
		when = fmt.Sprintf("expired on %s, %s ago", notAfter, days(-left))
	case left <= time.Duration(s.limits.warn)*day:
		findingType, title, severity = findingTypeExpiring, titleExpiring+displayHost(target), shared.SeverityMedium
		if left <= time.Duration(s.limits.critical)*day {
			severity = shared.SeverityHigh
		}
		when = fmt.Sprintf("expires on %s, in %s", notAfter, days(left))
	default:
		return shared.SecurityFinding{}, false
	}

	description := fmt.Sprintf("The TLS certificate that %s serves %s.\n\nSubject: %s\nIssuer: %s",
		target.Target, when, clip(cert.Subject.String()), clip(cert.Issuer.String()))
	if left <= 0 {
		description += "\n\nBrowsers and API clients refuse the connection with a certificate error."
	} else {
		description += "\n\nWhen it expires, browsers and API clients refuse the connection with a certificate error."
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,
		OrgID:       target.OrgID,
		Source:      findingSource,
		DiscoveryID: target.DiscoveryID,
		FindingType: findingType,
		Severity:    severity,
		Title:       title,
		Description: description,
		Remediation: "Renew the certificate and install it on the server, then reload the service. " +
			"If an ACME client (certbot, acme.sh, Caddy, Traefik, cert-manager) renews it automatically, " +
			"find out why the renewal did not run or was not loaded: check the client's logs and timer, " +
			"that the HTTP-01 or DNS-01 challenge still succeeds, and that the server reloads after renewal.",
		Metadata: map[string]interface{}{
			"target":    target.Target,
			"not_after": cert.NotAfter.UTC().Format(time.RFC3339),
			"days_left": int(math.Floor(left.Hours() / 24)),
			"subject":   clip(cert.Subject.String()),
			"issuer":    clip(cert.Issuer.String()),
		},
		Status:    shared.FindingStatusOpen,
		Timestamp: now,
	}, true
}

// displayHost is the host the title names: the hostname of a domain target (port 443 is
// implied), host:port otherwise.
func displayHost(target ScanTarget) string {
	host, port, err := net.SplitHostPort(target.Target)
	if err == nil && port == "443" {
		return host
	}
	return target.Target
}

// days renders a positive duration as whole days ("less than a day" below one).
func days(d time.Duration) string {
	n := int(d / (24 * time.Hour))
	switch n {
	case 0:
		return "less than a day"
	case 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

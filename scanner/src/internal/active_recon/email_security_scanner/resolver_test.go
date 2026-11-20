package email_security_scanner

import (
	"context"
	"net"
	"testing"
)

// fakeResolver answers every TXT lookup with txt and err.
type fakeResolver struct {
	txt []string
	err error
}

func (f fakeResolver) LookupTXT(context.Context, string) ([]string, error) { return f.txt, f.err }
func (f fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, f.err }
func (f fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, f.err }

var (
	notFound = &net.DNSError{Err: "no such host", IsNotFound: true}
	timeout  = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	spfRec   = []string{"v=spf1 include:_spf.example.com ~all"}
)

func TestConfirmingResolver(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name         string
		r            confirmingResolver
		wantRecords  bool
		wantNotFound bool
		wantErr      bool
	}{
		{"local answer is used", confirmingResolver{local: fakeResolver{txt: spfRec}, public: fakeResolver{err: timeout}}, true, false, false},
		{"local false NXDOMAIN: public record wins", confirmingResolver{local: fakeResolver{err: notFound}, public: fakeResolver{txt: spfRec}}, true, false, false},
		{"NXDOMAIN confirmed by public", confirmingResolver{local: fakeResolver{err: notFound}, public: fakeResolver{err: notFound}}, false, true, true},
		{"NXDOMAIN not confirmed: incomplete, not 'missing'", confirmingResolver{local: fakeResolver{err: notFound}, public: fakeResolver{err: timeout}}, false, false, true},
		{"recheck off: local NXDOMAIN is final", confirmingResolver{local: fakeResolver{err: notFound}}, false, true, true},
		{"local timeout is not rechecked", confirmingResolver{local: fakeResolver{err: timeout}, public: fakeResolver{txt: spfRec}}, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txt, err := tt.r.LookupTXT(ctx, "example.com")
			if (len(txt) > 0) != tt.wantRecords || (err != nil) != tt.wantErr || isDNSNotFound(err) != tt.wantNotFound {
				t.Fatalf("LookupTXT = %v, %v", txt, err)
			}
		})
	}
}

// TestCheckSPFIncompleteWhenNotFoundIsUnconfirmed: a false "no record" must not resolve the
// findings of the record that is really there, nor report a missing record.
func TestCheckSPFIncompleteWhenNotFoundIsUnconfirmed(t *testing.T) {
	r := confirmingResolver{local: fakeResolver{err: notFound}, public: fakeResolver{err: timeout}}
	results, err := checkSPF(context.Background(), r, "example.com")
	if err == nil || len(results) != 0 {
		t.Fatalf("checkSPF = %v, %v; want no result and an error", results, err)
	}
}

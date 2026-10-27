package mx

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

// fuzzResolver answers a lookup from the fuzz input and records the names it
// was asked for, so the target can check that the verifier looked up the
// domain it was given, and only that one.
type fuzzResolver struct {
	mx  []*net.MX
	err error

	mu    sync.Mutex
	names []string
}

func (r *fuzzResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	r.mu.Lock()
	r.names = append(r.names, name)
	r.mu.Unlock()
	return r.mx, r.err
}

func (r *fuzzResolver) asked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...)
}

// fuzzRecords splits the answer of the fuzzer into the records it holds:
// every newline ends one. An empty answer holds no record at all, and a lone
// newline holds one record with no host.
func fuzzRecords(raw string) []string {
	var records []string
	for {
		i := strings.IndexByte(raw, '\n')
		if i < 0 {
			return records
		}
		records = append(records, raw[:i])
		raw = raw[i+1:]
	}
}

// fuzzDomain is the domain of an address: the part after the last '@', found
// by scanning from the end.
func fuzzDomain(address string) string {
	for i := len(address) - 1; i >= 0; i-- {
		if address[i] == '@' {
			return address[i+1:]
		}
	}
	return ""
}

// fuzzFitsDNS reports whether a domain fits the size limits DNS puts on a
// name: at most 253 bytes in all, and every label between 1 and 63 bytes.
func fuzzFitsDNS(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	label := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if label == 0 || label > 63 {
				return false
			}
			label = 0
			continue
		}
		label++
	}
	return label >= 1 && label <= 63
}

// fuzzHasRealMX reports whether an answer names an exchanger: the null MX,
// the one record that names none, refuses the answer only when it is the
// only record in it.
func fuzzHasRealMX(hosts []string) bool {
	switch len(hosts) {
	case 0:
		return false
	case 1:
		return hosts[0] != "." && hosts[0] != ""
	default:
		return true
	}
}

// fuzzExpected is the outcome Verify must produce, written from the
// contract: an address that names no domain, or a domain that does not fit
// DNS, is refused without a lookup; a resolver that says the domain does
// not exist gives a definitive no-MX; a resolver that fails gives a domain
// that could not be resolved; and an answer that names an exchanger means the
// domain accepts mail.
func fuzzExpected(name string, hosts []string, notFound, failed bool) error {
	switch {
	case name == "":
		return errs.ErrDomainNoMX
	case !fuzzFitsDNS(name):
		return errs.ErrInvalidEmail
	case notFound:
		return errs.ErrDomainNoMX
	case failed:
		return errs.ErrDomainUnresolvable
	case fuzzHasRealMX(hosts):
		return nil
	default:
		return errs.ErrDomainNoMX
	}
}

// FuzzVerify drives the whole MX verification with an arbitrary address and
// an arbitrary answer from the resolver.
func FuzzVerify(f *testing.F) {
	f.Add("user@example.com", "mail.example.com.\n", uint8(0))
	f.Add("user@example.com", ".\n", uint8(0))
	f.Add("user@example.com", "", uint8(0))
	f.Add("user@example.com", "\n", uint8(0))
	f.Add("user@example.com", ".\n", uint8(1))
	f.Add("user@example.com", "mail.example.com.\n", uint8(2))
	f.Add("user@example.com", "mail.example.com.\n", uint8(3))
	f.Add("notanemail", "mail.example.com.\n", uint8(0))
	f.Add("user@", "mail.example.com.\n", uint8(0))
	f.Add("user@example.com", "", uint8(1))
	f.Add("user@", "", uint8(2))
	f.Add("", "", uint8(0))

	f.Fuzz(func(t *testing.T, address string, raw string, kind uint8) {
		if len(raw) > 1<<12 {
			// An answer of thousands of records is not what the contract is
			// about, and building one costs more than the check.
			t.Skip()
		}
		hosts := fuzzRecords(raw)
		records := make([]*net.MX, 0, len(hosts))
		for _, h := range hosts {
			records = append(records, &net.MX{Host: h, Pref: 10})
		}
		var lookupErr error
		notFound := false
		switch kind % 4 {
		case 1:
			lookupErr = &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
			notFound = true
		case 2:
			lookupErr = &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true}
		case 3:
			lookupErr = errors.New("the resolver is on fire")
		}

		resolver := &fuzzResolver{mx: records, err: lookupErr}
		verifier := New(resolver, time.Minute)
		err := verifier.Verify(context.Background(), address)

		name := fuzzDomain(address)
		want := fuzzExpected(name, hosts, notFound, lookupErr != nil)
		switch {
		case want == nil:
			if err != nil {
				t.Fatalf("Verify(%q) with the answer %q = %v, want no error", address, hosts, err)
			}
		case !errors.Is(err, want):
			t.Fatalf("Verify(%q) with the answer %q = %v, want %v", address, hosts, err, want)
		}

		asked := resolver.asked()
		if name == "" || !fuzzFitsDNS(name) {
			if len(asked) != 0 {
				t.Fatalf("Verify(%q) looked up %v, which is not a domain to look up", address, asked)
			}
			return
		}
		if len(asked) != 1 || asked[0] != name {
			t.Fatalf("Verify(%q) looked up %v, want exactly [%q]", address, asked, name)
		}
	})
}

// The domain a lookup is made for is the part after the last '@', so an
// address with several of them looks up the last one.
func TestFuzzVerifyLooksUpTheLastDomain(t *testing.T) {
	resolver := &fuzzResolver{mx: []*net.MX{{Host: "mail.example.com.", Pref: 10}}}
	verifier := New(resolver, time.Minute)
	if err := verifier.Verify(context.Background(), "a@b@example.com"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	asked := resolver.asked()
	if len(asked) != 1 || asked[0] != "example.com" {
		t.Fatalf("looked up %v, want exactly [example.com]", asked)
	}
}

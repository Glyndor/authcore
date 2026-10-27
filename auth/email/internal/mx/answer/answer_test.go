package answer

import (
	"errors"
	"net"
	"testing"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
	"github.com/Glyndor/authcore/auth/email/internal/mx/cache"
)

func TestHasRealMX(t *testing.T) {
	cases := []struct {
		name string
		mxs  []*net.MX
		want bool
	}{
		{"no records", nil, false},
		{"empty slice", []*net.MX{}, false},
		{"null MX with a dot", []*net.MX{{Host: ".", Pref: 0}}, false},
		{"null MX with an empty host", []*net.MX{{Host: "", Pref: 0}}, false},
		{"one real record", []*net.MX{{Host: "mail.example.com.", Pref: 10}}, true},
		{"a null record next to a real one", []*net.MX{{Host: ".", Pref: 0}, {Host: "mail.example.com.", Pref: 10}}, true},
	}
	for _, c := range cases {
		if got := HasRealMX(c.mxs); got != c.want {
			t.Errorf("%s: HasRealMX = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestErr(t *testing.T) {
	if err := Err(cache.Entry{HasMX: true}); err != nil {
		t.Errorf("an entry with MX records: %v, want nil", err)
	}
	if err := Err(cache.Entry{}); !errors.Is(err, errs.ErrDomainNoMX) {
		t.Errorf("an entry without MX records: %v, want errs.ErrDomainNoMX", err)
	}
	// A DNS failure is cached with HasMX false; it must not read as "no MX".
	err := Err(cache.Entry{DNSFailure: true})
	if !errors.Is(err, errs.ErrDomainUnresolvable) {
		t.Errorf("a cached DNS failure: %v, want errs.ErrDomainUnresolvable", err)
	}
	if errors.Is(err, errs.ErrDomainNoMX) {
		t.Error("a cached DNS failure must not be served as errs.ErrDomainNoMX")
	}
}

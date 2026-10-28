package memory_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: a provider whose discovery document is padded with members the
// client does not use, as long as an array or as deep a nesting as the body
// cap allows. The document is read up to the cap and a body over it is refused
// whole, so the price is a bounded multiple of the cap, whatever the provider
// sends. The bodies are served from memory: only the client is measured.

// discoveryBody returns the valid document of the remote issuer with the
// extra member spliced in as raw JSON.
func discoveryBody(t *testing.T, member, raw string) []byte {
	t.Helper()
	b, err := json.Marshal(hostiletest.GoodDoc(hostiletest.RemoteIssuer))
	if err != nil {
		t.Fatal(err)
	}
	return append(b[:len(b)-1], []byte(`,"`+member+`":`+raw+`}`)...)
}

func discover(t *testing.T, body []byte) error {
	t.Helper()
	hc := &http.Client{Transport: hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
		return hostiletest.MemResponse(r, http.StatusOK, body), nil
	})}
	_, err := oauth.Discover(hostiletest.Ctx(t), hostiletest.RemoteIssuer, hc)
	return err
}

// padded returns a document of at most size bytes whose extra member is open,
// then as many copies of unit as fit, then last and close.
func padded(t *testing.T, size int, member, open, unit, last, closing string) []byte {
	t.Helper()
	head := discoveryBody(t, member, open+last+closing)
	n := (size - len(head)) / len(unit)
	return discoveryBody(t, member, open+strings.Repeat(unit, n)+last+closing)
}

// nested returns a document of at most size bytes whose extra member is an
// array inside an array, as deep as that size allows.
func nested(t *testing.T, size int) []byte {
	t.Helper()
	k := (size - len(discoveryBody(t, "x", ""))) / 2
	return discoveryBody(t, "x", strings.Repeat("[", k)+strings.Repeat("]", k))
}

func TestHostile_Memory_aPaddedDiscoveryDocumentCostsABoundedMultipleOfTheCap(t *testing.T) {
	ordinary := discoveryBody(t, "scopes_supported", `["openid"]`)
	if err := discover(t, ordinary); err != nil {
		t.Fatalf("control: an ordinary document was refused: %v", err)
	}
	base, _ := allocOf(func() { _ = discover(t, ordinary) })

	const cap = hostiletest.ResponseCap
	cases := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{"an array of strings that fills the cap", padded(t, cap, "claims_supported", "[", `"c",`, `"c"`, "]"), false},
		{"an array of numbers that fills the cap", padded(t, cap, "claims_supported", "[", `1,`, `1`, "]"), false},
		{"an array of empty arrays that fills the cap", padded(t, cap, "claims_supported", "[", `[],`, `[]`, "]"), false},
		{"nesting that fills the cap", nested(t, cap), true},
		{"an array of strings eight times over the cap", padded(t, 8*cap, "claims_supported", "[", `"c",`, `"c"`, "]"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if (len(tc.body) > cap) != (tc.name == "an array of strings eight times over the cap") {
				t.Fatalf("test body of %d bytes is on the wrong side of the %d-byte cap", len(tc.body), cap)
			}
			var err error
			got, _ := allocOf(func() { err = discover(t, tc.body) })
			// Measured on 2026-10-28 at 2.1x the cap for a body over it and
			// 3.1x for the densest document under it; the bound is 6x the cap
			// over what an ordinary document costs.
			if limit := base + 6*cap; got > limit {
				t.Errorf("a %d-byte document allocated %d bytes, over %d (an ordinary one: %d)", len(tc.body), got, limit, base)
			}
			if tc.wantErr && err == nil {
				t.Fatal("a hostile document was accepted")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("a valid document padded with an unused member was refused: %v", err)
			}
			if err != nil && !errors.Is(err, oauth.ErrDiscovery) {
				t.Fatalf("refused, but not as ErrDiscovery: %v", err)
			}
		})
	}
}

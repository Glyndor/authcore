package responses_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: a provider that chooses the text of its error answers. Effect they
// want: the log line of the caller (which prints err.Error()) carries control
// characters or a volume of text the provider picked.

func TestHostile_Exchange_providerErrorTextIsPrintable(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"error":             "invalid_grant\nFATAL forged log line",
		"error_description": "\x1b[31mred\r\nERROR fake " + strings.Repeat("é", 400),
	})
	srv := hostiletest.Serve(t, hostiletest.StaticBody(body))
	_, err := hostiletest.TokenClient(t, srv.URL, nil).Exchange(hostiletest.Ctx(t), "code", "verifier")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("control: the error envelope was not refused as ErrExchange: %v", err)
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\n\r\x1b") {
		t.Errorf("the error carries provider-chosen control characters: %q", msg)
	}
	if !utf8.ValidString(msg) {
		t.Errorf("the error is not valid UTF-8: %q", msg)
	}
	if !strings.Contains(msg, "invalid_grant") {
		t.Errorf("the error lost the provider code: %q", msg)
	}
}

func TestHostile_Errors_providerControlledTextIsBounded(t *testing.T) {
	const limit = 4096
	t.Run("exchange error code", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"error": strings.Repeat("a", 900<<10)})
		srv := hostiletest.Serve(t, hostiletest.StaticBody(body))
		_, err := hostiletest.TokenClient(t, srv.URL, nil).Exchange(hostiletest.Ctx(t), "code", "verifier")
		if !errors.Is(err, oauth.ErrExchange) {
			t.Fatalf("control: the error envelope was not refused as ErrExchange: %v", err)
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
	t.Run("discovery issuer mismatch", func(t *testing.T) {
		srv := hostiletest.DiscoveryServer(t, func(doc map[string]any, _ string) { doc["issuer"] = strings.Repeat("a", 900<<10) })
		_, err := oauth.Discover(hostiletest.Ctx(t), srv.URL, nil)
		if !errors.Is(err, oauth.ErrDiscovery) {
			t.Fatalf("control: the document was not refused as ErrDiscovery: %v", err)
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
	t.Run("discovery endpoint", func(t *testing.T) {
		hc := hostiletest.RemoteDiscovery(hostiletest.RemoteIssuer, func(doc map[string]any) { doc["token_endpoint"] = "http://" + strings.Repeat("a", 900<<10) })
		_, err := oauth.Discover(hostiletest.Ctx(t), hostiletest.RemoteIssuer, hc)
		if !errors.Is(err, oauth.ErrDiscovery) {
			t.Fatalf("control: the document was not refused as ErrDiscovery: %v", err)
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
	t.Run("unknown key id", func(t *testing.T) {
		c, _ := hostiletest.JWKSClient(t, hostiletest.JWKSDoc())
		a, _ := hostiletest.RSAKeys()
		tok := hostiletest.Mint{Key: a, Kid: strings.Repeat("k", 12<<10), Claims: hostiletest.Claims(hostiletest.Nonce, nil)}.String(t)
		_, err := hostiletest.Verify(t, c, tok)
		if !errors.Is(err, oauth.ErrIDTokenInvalid) {
			t.Fatalf("control: the token was not refused as ErrIDTokenInvalid: %v", err)
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
}

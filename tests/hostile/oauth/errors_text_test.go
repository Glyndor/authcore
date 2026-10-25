package hostile_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: a provider that chooses the text of its error answers. Effect they
// want: the log line of the caller (which prints err.Error()) carries control
// characters or a volume of text the provider picked.

func TestHostile_Exchange_providerErrorTextIsPrintable(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"error":             "invalid_grant\nFATAL forged log line",
		"error_description": "\x1b[31mred\r\nERROR fake " + strings.Repeat("é", 400),
	})
	srv := serve(t, staticBody(body))
	_, err := tokenClient(t, srv.URL, nil).Exchange(ctx(t), "code", "verifier")
	if err == nil {
		t.Fatal("control: the error envelope was accepted")
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
		srv := serve(t, staticBody(body))
		_, err := tokenClient(t, srv.URL, nil).Exchange(ctx(t), "code", "verifier")
		if err == nil {
			t.Fatal("control: the error envelope was accepted")
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
	t.Run("discovery issuer mismatch", func(t *testing.T) {
		srv := discoveryServer(t, func(doc map[string]any, _ string) { doc["issuer"] = strings.Repeat("a", 900<<10) })
		_, err := oauth.Discover(ctx(t), srv.URL, nil)
		if err == nil {
			t.Fatal("control: the document was accepted")
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
	t.Run("discovery endpoint", func(t *testing.T) {
		hc := remoteDiscovery(remoteIssuer, func(doc map[string]any) { doc["token_endpoint"] = "http://" + strings.Repeat("a", 900<<10) })
		_, err := oauth.Discover(ctx(t), remoteIssuer, hc)
		if err == nil {
			t.Fatal("control: the document was accepted")
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
	t.Run("unknown key id", func(t *testing.T) {
		c, _ := jwksClient(t, jwksDoc())
		a, _ := rsaKeys()
		tok := mint{Key: a, Kid: strings.Repeat("k", 12<<10), Claims: claims(testNonce, nil)}.String(t)
		_, err := verify(t, c, tok)
		if err == nil {
			t.Fatal("control: the token was accepted")
		}
		if len(err.Error()) > limit {
			t.Fatalf("the error text is %d bytes", len(err.Error()))
		}
	})
}

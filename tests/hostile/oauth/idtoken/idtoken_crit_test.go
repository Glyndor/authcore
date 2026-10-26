package idtoken_test

import (
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// RFC 7515 section 4.1.11: a JWS that lists a critical extension the recipient
// does not understand is invalid. The verifier understands none.
func TestHostile_IDToken_criticalHeaderIsRefused(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	srv := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.StdJWKS(t)))
	c := hostiletest.OIDCClient(t, srv.URL, nil)
	for _, crit := range []any{[]string{"https://evil.example/ext"}, []string{}, "b64", []any{nil}} {
		tok := hostiletest.Mint{Key: a, Claims: hostiletest.Claims(hostiletest.Nonce, nil), Header: map[string]any{"crit": crit}}.String(t)
		got, err := hostiletest.Verify(t, c, tok)
		hostiletest.MustRejectToken(t, got, err)
	}
}

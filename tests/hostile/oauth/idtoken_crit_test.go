package hostile_test

import "testing"

// RFC 7515 section 4.1.11: a JWS that lists a critical extension the recipient
// does not understand is invalid. The verifier understands none.
func TestHostile_IDToken_criticalHeaderIsRefused(t *testing.T) {
	a, _ := rsaKeys()
	srv := serve(t, staticBody(stdJWKS(t)))
	c := oidcClient(t, srv.URL, nil)
	for _, crit := range []any{[]string{"https://evil.example/ext"}, []string{}, "b64", []any{nil}} {
		tok := mint{Key: a, Claims: claims(testNonce, nil), Header: map[string]any{"crit": crit}}.String(t)
		got, err := verify(t, c, tok)
		mustRejectToken(t, got, err)
	}
}

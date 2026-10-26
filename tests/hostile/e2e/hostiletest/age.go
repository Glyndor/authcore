package hostiletest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Age returns token as if the clock had moved d forward since it was issued:
// iat, nbf and exp of the payload move d back and the result is signed again
// with the Env's key, header untouched. The module reads a real clock, so this
// is how a test advances time without sleeping. d is cut to whole seconds.
// An Env other than the issuing one gives a token the verifier must refuse.
func Age(t testing.TB, e *Env, token string, d time.Duration) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	Check(t, err)
	var payload map[string]any
	Check(t, json.Unmarshal(raw, &payload))
	for _, k := range []string{"iat", "nbf", "exp"} {
		if v, ok := payload[k].(float64); ok {
			payload[k] = v - float64(int64(d/time.Second))
		}
	}
	raw, err = json.Marshal(payload)
	Check(t, err)
	signed := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
	sig := ed25519.Sign(e.Priv, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

package hostiletest

import (
	"encoding/json"
	"strings"
	"testing"
)

// JSONNull is a JSON null, to put in a claim set that must carry a null member.
var JSONNull = json.RawMessage("null")

// StdJWKS publishes the first RSA key under KID.
func StdJWKS(*testing.T) []byte {
	a, _ := RSAKeys()
	return JWKSDoc(RSAJWK(KID, &a.PublicKey, nil))
}

// SignA signs claims c with the first RSA key under KID.
func SignA(t *testing.T, c map[string]any) string {
	t.Helper()
	a, _ := RSAKeys()
	return Mint{Key: a, Claims: c}.String(t)
}

// ResponseCap is the largest response body, in bytes, the client reads.
const ResponseCap = 1 << 20

// TokenBody renders the fields of a token response; a nil value drops the key,
// and "raw:" values are spliced in without quoting.
func TokenBody(fields map[string]string) []byte {
	var parts []string
	for k, v := range fields {
		if v == "" {
			continue
		}
		val := v
		if !strings.HasPrefix(v, "raw:") {
			b, _ := json.Marshal(v)
			val = string(b)
		} else {
			val = strings.TrimPrefix(v, "raw:")
		}
		kb, _ := json.Marshal(k)
		parts = append(parts, string(kb)+":"+val)
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

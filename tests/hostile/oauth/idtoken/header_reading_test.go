package idtoken_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func signRawReading(t *testing.T, header, payload string) string {
	t.Helper()
	input := hostiletest.B64([]byte(header)) + "." + hostiletest.B64([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	key, _ := hostiletest.RSAKeys()
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + hostiletest.B64(signature)
}

func rawReadingClaims(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(hostiletest.Claims(hostiletest.Nonce, nil))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestHostile_IDTokenHasOneReading(t *testing.T) {
	p := hostiletest.NewMemProvider(hostiletest.StdJWKS(t))
	c := p.BubbleClient(t, nil)
	header, payload := `{"alg":"RS256","kid":"k1"}`, rawReadingClaims(t)
	for _, field := range []string{"alg", "kid", "sub", "iss", "aud", "nonce"} {
		for _, alias := range []string{field, strings.ToUpper(field), `\u00` + string("0123456789abcdef"[field[0]>>4]) + string("0123456789abcdef"[field[0]&15]) + field[1:]} {
			for _, reverse := range []bool{false, true} {
				t.Run(field+"/"+alias+map[bool]string{false: "/first", true: "/last"}[reverse], func(t *testing.T) {
					h, b := header, payload
					value := map[string]string{"alg": "RS256", "kid": "k1", "sub": "other", "iss": hostiletest.Issuer, "aud": hostiletest.ClientID, "nonce": hostiletest.Nonce}[field]
					extra := `"` + alias + `":"` + value + `",`
					if field == "alg" || field == "kid" {
						if reverse {
							h = h[:len(h)-1] + `,` + extra[:len(extra)-1] + `}`
						} else {
							h = `{` + extra + h[1:]
						}
					} else {
						if reverse {
							b = b[:len(b)-1] + `,` + extra[:len(extra)-1] + `}`
						} else {
							b = `{` + extra + b[1:]
						}
					}
					got, err := hostiletest.Verify(t, c, signRawReading(t, h, b))
					if got != nil {
						t.Fatalf("ambiguous token returned claims: %+v", got)
					}
					hostiletest.MustRejectToken(t, got, err)
				})
			}
		}
	}
	got, err := hostiletest.Verify(t, c, signRawReading(t, header, payload[:len(payload)-1]+`,"nested":{"sub":"inner"},"items":[{"id":1},{"id":2}]}`))
	if err != nil || got == nil {
		t.Fatalf("legitimate token: claims=%v err=%v", got, err)
	}
}

func TestHostile_NonStringKidCannotSelectAnonymousKey(t *testing.T) {
	key, _ := hostiletest.RSAKeys()
	p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK("", &key.PublicKey, nil)))
	c := p.BubbleClient(t, nil)
	payload := rawReadingClaims(t)
	for _, raw := range []string{"1", "true", "null", `["k1"]`, `{}`} {
		t.Run(raw, func(t *testing.T) {
			got, err := hostiletest.Verify(t, c, signRawReading(t, `{"alg":"RS256","kid":`+raw+`}`, payload))
			if got != nil {
				t.Fatalf("non-string kid returned claims: %+v", got)
			}
			hostiletest.MustRejectToken(t, got, err)
		})
	}
	got, err := hostiletest.Verify(t, c, signRawReading(t, `{"alg":"RS256"}`, payload))
	if err != nil || got == nil {
		t.Fatalf("absent kid control: claims=%v err=%v", got, err)
	}
}

func TestHostile_HeaderKidIsNeverRepaired(t *testing.T) {
	key, _ := hostiletest.RSAKeys()
	payload := rawReadingClaims(t)
	for _, tc := range []struct {
		kid, raw string
		valid    bool
	}{
		{"k�", `"k�"`, true}, {"k�", `"k\ufffd"`, true}, {"k😀", `"k\ud83d\ude00"`, true},
		{"k�", "\"k\xff\"", false}, {"k�", `"k\ud800"`, false}, {"k�", `"k\udc00"`, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK(tc.kid, &key.PublicKey, nil)))
			got, err := hostiletest.Verify(t, p.BubbleClient(t, nil), signRawReading(t, `{"alg":"RS256","kid":`+tc.raw+`}`, payload))
			if tc.valid {
				if err != nil || got == nil {
					t.Fatalf("valid Unicode kid: claims=%v err=%v", got, err)
				}
			} else {
				if got != nil {
					t.Fatalf("repaired kid returned claims: %+v", got)
				}
				hostiletest.MustRejectToken(t, got, err)
			}
		})
	}
}

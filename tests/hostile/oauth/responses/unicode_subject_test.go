package responses_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Sign the original JSON bytes so the fixture does not repair the subject.
func signedRawSubject(t *testing.T, raw string) string {
	t.Helper()
	claims, err := json.Marshal(hostiletest.Claims(hostiletest.Nonce, map[string]any{"sub": "subject-placeholder"}))
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Replace(string(claims), `"subject-placeholder"`, raw, 1)
	header := `{"alg":"RS256","kid":"` + hostiletest.KID + `","typ":"JWT"}`
	input := hostiletest.B64([]byte(header)) + "." + hostiletest.B64([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	key, _ := hostiletest.RSAKeys()
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + hostiletest.B64(signature)
}

func TestHostile_OAuth_InvalidUnicodeNeverAliasesAnotherSubject(t *testing.T) {
	cases := []struct {
		name, raw, want string
		valid           bool
	}{
		{"replacement-control", `"user-\ufffd"`, "user-�", true},
		{"paired-surrogates-control", `"user-\ud83d\ude00"`, "user-😀", true},
		{"invalid-utf8-ff", "\"user-\xff\"", "", false},
		{"invalid-utf8-fe", "\"user-\xfe\"", "", false},
		{"lone-high-d800", `"user-\ud800"`, "", false},
		{"lone-high-d801", `"user-\ud801"`, "", false},
		{"lone-low-dc00", `"user-\udc00"`, "", false},
	}
	t.Run("userinfo", func(t *testing.T) {
		for _, field := range []string{"id", "sub"} {
			for _, tc := range cases {
				t.Run(field+"/"+tc.name, func(t *testing.T) {
					body := []byte(`{"` + field + `":` + tc.raw + `}`)
					hc := &http.Client{Transport: hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
						return hostiletest.MemResponse(r, http.StatusOK, body), nil
					})}
					c := hostiletest.UserinfoClient(t, "https://idp.example/userinfo", func(cfg *oauth.Config) { cfg.HTTPClient = hc })
					got, err := c.UserInfo(hostiletest.Ctx(t), "access-token")
					if tc.valid {
						if err != nil || got[field] != tc.want {
							t.Fatalf("valid Unicode control: profile=%v err=%v", got, err)
						}
					} else if got != nil || !errors.Is(err, oauth.ErrUserInfo) {
						t.Errorf("malformed identity must be refused: profile=%v err=%v", got, err)
					}
				})
			}
		}
	})
	t.Run("idtoken", func(t *testing.T) {
		p := hostiletest.NewMemProvider(hostiletest.StdJWKS(t))
		c := p.BubbleClient(t, nil)
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := hostiletest.Verify(t, c, signedRawSubject(t, tc.raw))
				if tc.valid {
					if err != nil || got == nil || got.Subject != tc.want {
						t.Fatalf("valid signed Unicode control: claims=%v err=%v", got, err)
					}
				} else {
					hostiletest.MustRejectToken(t, got, err)
				}
			})
		}
	})
}

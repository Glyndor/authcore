package responses_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_OAuth_ResponseCapRejectsValidPrefixWithHiddenSuffix(t *testing.T) {
	discovery, err := json.Marshal(hostiletest.GoodDoc(hostiletest.Issuer))
	if err != nil {
		t.Fatal(err)
	}
	jwks := hostiletest.StdJWKS(t)
	token := hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))
	for _, endpoint := range []struct {
		name string
		doc  []byte
	}{
		{"discovery", discovery}, {"jwks", jwks},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			if len(endpoint.doc) >= hostiletest.ResponseCap {
				t.Fatal("fixture document exceeds cap")
			}
			capped := append(bytes.Clone(endpoint.doc), bytes.Repeat([]byte(" "), hostiletest.ResponseCap-len(endpoint.doc))...)
			for _, tc := range []struct {
				name   string
				body   []byte
				accept bool
			}{
				{"under-cap-control", endpoint.doc, true},
				{"exact-cap-control", capped, true},
				{"visible-junk-control", append(bytes.Clone(endpoint.doc), '!'), false},
				{"visible-document-control", append(bytes.Clone(endpoint.doc), []byte(`{}`)...), false},
				{"hidden-junk", append(bytes.Clone(capped), '!'), false},
				{"hidden-document", append(bytes.Clone(capped), []byte(`{}`)...), false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					hits := 0
					hc := &http.Client{Transport: hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
						hits++
						response := hostiletest.MemResponse(r, http.StatusOK, tc.body)
						response.ContentLength = -1 // The bound must also hold without a length header.
						return response, nil
					})}
					var err error
					if endpoint.name == "discovery" {
						got, discoverErr := oauth.Discover(hostiletest.Ctx(t), hostiletest.Issuer, hc)
						err = discoverErr
						if tc.accept && (err != nil || got.JWKSURL != hostiletest.Issuer+"/jwks") {
							t.Fatalf("valid discovery control: provider=%v err=%v", got, err)
						}
						if !tc.accept && !errors.Is(err, oauth.ErrDiscovery) {
							t.Errorf("response with trailing data was not refused as ErrDiscovery: %v", err)
						}
					} else {
						c := hostiletest.OIDCClient(t, hostiletest.Issuer+"/jwks", func(cfg *oauth.Config) { cfg.HTTPClient = hc })
						got, verifyErr := hostiletest.Verify(t, c, token)
						err = verifyErr
						if tc.accept {
							if err != nil || got == nil || got.Subject != "user-abc" {
								t.Fatalf("valid JWKS control: claims=%v err=%v", got, err)
							}
						} else {
							hostiletest.MustRejectToken(t, got, err)
						}
					}
					if hits != 1 {
						t.Errorf("fixture requests = %d, want 1", hits)
					}
				})
			}
		})
	}
}

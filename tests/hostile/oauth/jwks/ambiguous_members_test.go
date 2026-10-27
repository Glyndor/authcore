package jwks_test

import (
	"encoding/json"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_JWKS_AmbiguousMembersCannotRelaxKeyRestrictions(t *testing.T) {
	key, _ := hostiletest.RSAKeys()
	token := hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))
	base, err := json.Marshal(hostiletest.RSAJWK(hostiletest.KID, &key.PublicKey, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, members string
		accept        bool
	}{
		{"signing-control", `"use":"sig","alg":"RS256","key_ops":["verify"]`, true},
		{"encryption-control", `"use":"enc"`, false},
		{"algorithm-control", `"alg":"RS512"`, false},
		{"operations-control", `"key_ops":["encrypt"]`, false},
		{"use-lower-first", `"use":"enc","USE":"sig"`, false},
		{"use-upper-first", `"USE":"sig","use":"enc"`, false},
		{"alg-lower-first", `"alg":"RS512","ALG":"RS256"`, false},
		{"alg-upper-first", `"ALG":"RS256","alg":"RS512"`, false},
		{"ops-lower-first", `"key_ops":["encrypt"],"KEY_OPS":["verify"]`, false},
		{"ops-upper-first", `"KEY_OPS":["verify"],"key_ops":["encrypt"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := []byte(`{"keys":[` + string(base[:len(base)-1]) + `,` + tc.members + `}]}`)
			provider := hostiletest.NewMemProvider(doc)
			claims, err := hostiletest.Verify(t, provider.BubbleClient(t, nil), token)
			if provider.JWKSHits.Load() == 0 {
				t.Fatal("fixture never fetched JWKS")
			}
			if tc.accept {
				if err != nil || claims == nil || claims.Subject != "user-abc" {
					t.Fatalf("signing control: claims=%v err=%v", claims, err)
				}
			} else {
				hostiletest.MustRejectToken(t, claims, err)
			}
		})
	}
}

package hostiletest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"testing"
	"time"
)

const (
	// ClientID is the OAuth client id every fixture registers.
	ClientID = "client-123"
	// Issuer is the issuer of the OIDC fixtures.
	Issuer = "https://idp.example"
	// KID is the key id of the provider signing key.
	KID = "k1"
	// Nonce is the nonce the callback expects.
	Nonce = "nonce-abc"
)

// Mint describes one hand-built compact JWS. Building the token by hand is the
// point: an attacker is not bound by what a JWT library is willing to emit.
type Mint struct {
	Alg    string // "RS256" when empty; also PS*, ES*, HS*, and the spellings of "none"
	Key    *rsa.PrivateKey
	EC     *ecdsa.PrivateKey
	HMAC   []byte
	Header map[string]any // merged over {alg, typ, kid}; a nil value deletes the member
	Claims map[string]any
	// Kid is the "kid" header: testKID when empty, omitted when "-".
	Kid string
}

func (m Mint) String(t *testing.T) string {
	t.Helper()
	alg := m.Alg
	if alg == "" {
		alg = "RS256"
	}
	header := map[string]any{"alg": alg, "typ": "JWT"}
	switch m.Kid {
	case "":
		header["kid"] = KID
	case "-":
	default:
		header["kid"] = m.Kid
	}
	for name, v := range m.Header {
		if v == nil {
			delete(header, name)
			continue
		}
		header[name] = v
	}
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	c, err := json.Marshal(m.Claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	input := B64(h) + "." + B64(c)
	return input + "." + B64(m.sign(t, alg, []byte(input)))
}

func (m Mint) sign(t *testing.T, alg string, input []byte) []byte {
	t.Helper()
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		h := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}[alg[2:]]
		d := Digest(h, input)
		var sig []byte
		var err error
		if alg[0] == 'R' {
			sig, err = rsa.SignPKCS1v15(rand.Reader, m.Key, h, d)
		} else {
			sig, err = rsa.SignPSS(rand.Reader, m.Key, h, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			t.Fatalf("sign %s: %v", alg, err)
		}
		return sig
	case "ES256", "ES384", "ES512":
		h := map[string]crypto.Hash{"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512}[alg]
		r, s, err := ecdsa.Sign(rand.Reader, m.EC, Digest(h, input))
		if err != nil {
			t.Fatalf("sign %s: %v", alg, err)
		}
		size := (m.EC.Curve.Params().BitSize + 7) / 8
		return append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	case "HS256", "HS384", "HS512":
		newHash := map[string]func() hash.Hash{"HS256": sha256.New, "HS384": sha512.New384, "HS512": sha512.New}[alg]
		mac := hmac.New(newHash, m.HMAC)
		mac.Write(input)
		return mac.Sum(nil)
	case "none", "None", "NONE", "nOnE":
		return nil
	}
	t.Fatalf("mint: unsupported alg %q", alg)
	return nil
}

// Digest hashes in with h.
func Digest(h crypto.Hash, in []byte) []byte {
	hh := h.New()
	hh.Write(in)
	return hh.Sum(nil)
}

// Claims returns a claim set the verifier accepts, with overrides merged in.
// A nil override deletes the claim.
func Claims(nonce string, over map[string]any) map[string]any {
	c := map[string]any{
		"iss": Issuer, "aud": ClientID, "sub": "user-abc",
		"email": "a@example.com", "email_verified": true, "nonce": nonce,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	for name, v := range over {
		if v == nil {
			delete(c, name)
			continue
		}
		c[name] = v
	}
	return c
}

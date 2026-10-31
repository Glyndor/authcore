package apple_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Glyndor/authcore/auth/oauth/internal/apple"
)

var errFuzzApple = errors.New("oauth: invalid configuration")

// FuzzClientSecret compares acceptance with a standard-library key parser and
// checks the signature, identifiers and five-minute lifetime of every secret.
func FuzzClientSecret(f *testing.F) {
	seed := sha256.Sum256([]byte("apple client secret fuzz key"))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
	if err != nil {
		f.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		f.Fatal(err)
	}
	good := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	f.Add(good, "ABCDE12345", "KEYID67890", "com.example.services")
	f.Add(append([]byte("junk\n"), good...), "ABCDE12345", "KEYID67890", "com.example.services")
	f.Add(append([]byte("-----BEGIN PRIVATE KEY-----\ninvalid!\n"), good...), "ABCDE12345", "KEYID67890", "com.example.services")
	f.Add(append(append([]byte(nil), good...), good...), "ABCDE12345", "KEYID67890", "com.example.services")
	f.Add(good, "abcde12345", "KEYID67890", "com.example.services")
	f.Add(good, "ABCDE1234", "KEYID67890", "com.example.services")
	f.Add(good, "ABCDE12345", "KEYID678901", "com.example.services")
	f.Add(good, "ABCDE12345", "KEYID67890", "com.example.services\n")
	f.Add(good, "ABCDE12345", "KEYID67890", " x")
	f.Add(good[:len(good)/2], "ABCDE12345", "KEYID67890", "x")
	f.Add([]byte{}, "", "", "")
	f.Add(good, "ZXCVB98765", "QWERT12345", "service/é\\\"value")

	f.Fuzz(func(t *testing.T, p8 []byte, team, keyID, client string) {
		// JSON strings preserve only valid UTF-8; compare opaque IDs in that domain.
		if !utf8.ValidString(client) {
			t.Skip("client ID is outside the JSON string domain")
		}
		ec := oracleAppleKey(p8)
		want := ec != nil && client != "" && strings.TrimSpace(client) == client
		for _, id := range []string{team, keyID} {
			want = want && len(id) == 10 && strings.Trim(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == ""
		}
		sign, err := apple.ClientSecret(errFuzzApple, team, keyID, client, p8)
		if (err == nil) != want {
			t.Fatalf("builder acceptance = %v, want %v: %v", err == nil, want, err)
		}
		if err != nil {
			if !errors.Is(err, errFuzzApple) {
				t.Fatalf("a refusal that does not wrap the config sentinel: %v", err)
			}
			return
		}
		before := time.Now().Unix()
		secret, err := sign(context.Background())
		if err != nil {
			t.Fatalf("a builder that was returned could not sign: %v", err)
		}
		after := time.Now().Unix()
		parts := strings.Split(secret, ".")
		if len(parts) != 3 {
			t.Fatalf("malformed secret %q", secret)
		}
		sig, derr := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
		if derr != nil || len(sig) != 64 {
			t.Fatalf("malformed secret %q", secret)
		}
		oracleAppleClaims(t, parts, team, keyID, client, before, after)
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if !ecdsa.Verify(&ec.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("the secret does not verify under the configured key")
		}
	})
}

// oracleAppleKey accepts one clean PKCS#8 P-256 PEM block using only the
// standard library, independently of the builder's validation helpers.
func oracleAppleKey(p8 []byte) *ecdsa.PrivateKey {
	trimmed := bytes.TrimSpace(p8)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) ||
		bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
		return nil
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	ec, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || ec.Curve != elliptic.P256() {
		return nil
	}
	return ec
}

func oracleAppleClaims(t *testing.T, parts []string, team, keyID, client string, before, after int64) {
	t.Helper()
	objects := make([]map[string]any, 2)
	for i := range objects {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&objects[i]); err != nil {
			t.Fatalf("invalid JWT JSON: %v", err)
		}
	}
	header, claims := objects[0], objects[1]
	if header["alg"] != "ES256" || header["kid"] != keyID {
		t.Fatalf("wrong JWT header: %v", header)
	}
	if claims["iss"] != team || claims["sub"] != client || claims["aud"] != "https://appleid.apple.com" {
		t.Fatalf("wrong JWT identity: %v", claims)
	}
	iat, iatOK := claims["iat"].(json.Number)
	exp, expOK := claims["exp"].(json.Number)
	issued, iatErr := iat.Int64()
	expires, expErr := exp.Int64()
	if !iatOK || !expOK || iatErr != nil || expErr != nil {
		t.Fatalf("iat/exp must be integer NumericDates: %v", claims)
	}
	if issued < before || issued > after || expires != issued+300 {
		t.Fatalf("iat/exp = %d/%d, signing window = [%d,%d], lifetime = 300s", issued, expires, before, after)
	}
}

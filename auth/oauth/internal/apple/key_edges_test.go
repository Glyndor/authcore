package apple_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/apple"
)

var errInvalid = errors.New("invalid apple config")

func p8(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Every one of the ten bytes of a team or key id is checked, the first
// included.
func TestClientSecretChecksEveryByteOfTheIdentifiers(t *testing.T) {
	t.Parallel()
	key := p8(t)
	if _, err := apple.ClientSecret(errInvalid, "ABCDE12345", "KEYID67890", "com.example.web", key); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, bad := range []string{"!BCDE12345", "ABCDE1234!", "ABC!E12345"} {
		if _, err := apple.ClientSecret(errInvalid, bad, "KEYID67890", "com.example.web", key); !errors.Is(err, errInvalid) {
			t.Errorf("team ID %q accepted (err=%v)", bad, err)
		}
		if _, err := apple.ClientSecret(errInvalid, "ABCDE12345", bad, "com.example.web", key); !errors.Is(err, errInvalid) {
			t.Errorf("key ID %q accepted (err=%v)", bad, err)
		}
	}
}

func TestClientSecretSaysWhenTheKeyBytesAreNotPKCS8(t *testing.T) {
	t.Parallel()
	junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a der structure")})
	_, err := apple.ClientSecret(errInvalid, "ABCDE12345", "KEYID67890", "com.example.web", junk)
	if !errors.Is(err, errInvalid) || !strings.Contains(err.Error(), "not a valid PKCS#8") {
		t.Fatalf("err = %v, want a refusal naming PKCS#8", err)
	}
}

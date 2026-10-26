package hostiletest

import (
	"crypto"
	"crypto/hmac"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"
)

// NewPEM returns a PKCS#8 private key PEM, a PKIX public key PEM and a random
// 32-byte refresh secret, the three inputs of authcore.NewKeyStoreFromPEM.
func NewPEM(t testing.TB) (priv, pub, secret []byte) {
	t.Helper()
	m := NewMaterial(t)
	der, err := x509.MarshalPKCS8PrivateKey(m.Priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(m.Pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
		m.Secret
}

// TOTPCode returns the RFC 6238 code (SHA-1, 30 s, 6 digits) that secretB32
// yields at instant at, computed independently of the library's code path.
// SHA-1 comes from the crypto registry rather than an import of crypto/sha1:
// auth/totp registers it, and tests/meta keeps new direct imports out.
func TOTPCode(t testing.TB, secretB32 string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secretB32, "=")))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if !crypto.SHA1.Available() {
		t.Fatal("SHA-1 is not linked into the test binary; the totp package registers it")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30)) // #nosec G115 -- the instant is after 1970
	mac := hmac.New(crypto.SHA1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", bin%1_000_000)
}

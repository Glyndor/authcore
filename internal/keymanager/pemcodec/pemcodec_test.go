package pemcodec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func pair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, []byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub, privPEM, pubPEM
}

func TestEncodeDecode_roundTrip(t *testing.T) {
	priv, pub, privPEM, pubPEM := pair(t)

	gotPriv, err := DecodeEd25519PrivatePEM(privPEM, "test")
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private round trip: %v", err)
	}
	gotPub, err := DecodeEd25519PublicPEM(pubPEM, "test")
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public round trip: %v", err)
	}
}

func TestEncode_labelsAndShape(t *testing.T) {
	_, _, privPEM, pubPEM := pair(t)
	if !strings.HasPrefix(string(privPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("private key PEM is labelled %q", privPEM[:30])
	}
	if !strings.HasPrefix(string(pubPEM), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("public key PEM is labelled %q", pubPEM[:30])
	}
}

// The decoders accept one block, of the expected type, with no headers and
// nothing else in the input. pem.Decode alone returned the first block
// wherever it sat and ignored the rest.
func TestDecodePEMBlock_acceptsOneCanonicalBlockOnly(t *testing.T) {
	_, _, privPEM, pubPEM := pair(t)
	_, _, otherPriv, _ := pair(t)

	if _, err := DecodePEMBlock(append([]byte("\n"), append(privPEM, '\n', '\n')...), "PRIVATE KEY", "test"); err != nil {
		t.Fatalf("whitespace around the block: %v, want accepted", err)
	}

	block, _ := pem.Decode(privPEM)
	relabelled := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: block.Bytes})
	for name, tc := range map[string]struct {
		in     []byte
		reason string
	}{
		"two private blocks":      {append(append([]byte{}, privPEM...), otherPriv...), "more than one PEM block"},
		"text before the block":   {append([]byte("Bag Attributes\n    friendlyName: k\n"), privPEM...), "does not start with a PEM block"},
		"text after the block":    {append(append([]byte{}, privPEM...), []byte("trailing note\n")...), "more than one PEM block, or text after it"},
		"CERTIFICATE label":       {relabelled, `labelled "CERTIFICATE", want "PRIVATE KEY"`},
		"encryption headers":      {withHeaders, "carries headers"},
		"public key as private":   {pubPEM, `labelled "PUBLIC KEY", want "PRIVATE KEY"`},
		"BEGIN line and no block": {[]byte("-----BEGIN PRIVATE KEY-----\nnot a block\n"), "no PEM block found"},
		"empty":                   {nil, "does not start with a PEM block"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodePEMBlock(tc.in, "PRIVATE KEY", "test")
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("DecodePEMBlock = %v, want a refusal naming %q", err, tc.reason)
			}
		})
	}
}

func TestDecode_rejectsGarbageInsideAWellFormedBlock(t *testing.T) {
	junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")})
	if _, err := DecodeEd25519PrivatePEM(junk, "test"); err == nil || !strings.Contains(err.Error(), "parse PKCS#8 private key") {
		t.Errorf("private: %v", err)
	}
	junk = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not der")})
	if _, err := DecodeEd25519PublicPEM(junk, "test"); err == nil || !strings.Contains(err.Error(), "parse PKIX public key") {
		t.Errorf("public: %v", err)
	}
}

func TestDecode_rejectsOtherKeyAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := DecodeEd25519PrivatePEM(rsaPriv, "test"); err == nil || !strings.Contains(err.Error(), "not an Ed25519 private key") {
		t.Errorf("RSA private key: %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if _, err := DecodeEd25519PublicPEM(ecPub, "test"); err == nil || !strings.Contains(err.Error(), "not an Ed25519 public key") {
		t.Errorf("ECDSA public key: %v", err)
	}
}

func TestDecode_labelMismatchBetweenPrivateAndPublic(t *testing.T) {
	_, _, privPEM, pubPEM := pair(t)
	if _, err := DecodeEd25519PublicPEM(privPEM, "test"); err == nil || !strings.Contains(err.Error(), `labelled "PRIVATE KEY", want "PUBLIC KEY"`) {
		t.Errorf("private key in the public slot: %v", err)
	}
	if _, err := DecodeEd25519PrivatePEM(pubPEM, "test"); err == nil || !strings.Contains(err.Error(), `labelled "PUBLIC KEY", want "PRIVATE KEY"`) {
		t.Errorf("public key in the private slot: %v", err)
	}
}

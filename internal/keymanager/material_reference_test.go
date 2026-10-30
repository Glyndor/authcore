package keymanager_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
)

// referenceDegenerate restates the documented rule for a secret or seed that
// cannot be random-looking: a constant stride, one short block repeated, or
// fewer than twelve different byte values.
func referenceDegenerate(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	stride := true
	for i := 2; i < len(b); i++ {
		if b[i]-b[i-1] != b[1]-b[0] {
			stride = false
		}
	}
	if stride {
		return true
	}
	for period := 2; period <= len(b)/2; period++ {
		if bytes.Equal(b[period:], b[:len(b)-period]) {
			return true
		}
	}
	var seen [256]bool
	distinct := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	return distinct < 12
}

// referenceDER returns the DER of the only PEM block in data, labelled label,
// with no headers and nothing else but whitespace around it.
func referenceDER(data []byte, label string) ([]byte, bool) {
	trimmed := bytes.TrimSpace(data)
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != label || len(block.Headers) != 0 {
		return nil, false
	}
	if len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, false
	}
	if bytes.Count(trimmed[:len(trimmed)-len(rest)], []byte("-----BEGIN ")) != 1 {
		return nil, false
	}
	return block.Bytes, true
}

// referenceKeys decodes the PEM inputs with the standard library only and
// applies the material contract: a consistent Ed25519 pair, a 32-byte secret,
// and neither seed nor secret degenerate. ok is false when any rule fails.
func referenceKeys(privPEM, pubPEM, secret []byte) (priv ed25519.PrivateKey, pub ed25519.PublicKey, ok bool) {
	privDER, okPriv := referenceDER(privPEM, "PRIVATE KEY")
	pubDER, okPub := referenceDER(pubPEM, "PUBLIC KEY")
	if !okPriv || !okPub {
		return nil, nil, false
	}
	rawPriv, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, nil, false
	}
	rawPub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, nil, false
	}
	priv, okPriv = rawPriv.(ed25519.PrivateKey)
	pub, okPub = rawPub.(ed25519.PublicKey)
	if !okPriv || !okPub || !ed25519.NewKeyFromSeed(priv.Seed()).Equal(priv) || !priv.Public().(ed25519.PublicKey).Equal(pub) {
		return nil, nil, false
	}
	if len(secret) != 32 || referenceDegenerate(priv.Seed()) || referenceDegenerate(secret) {
		return nil, nil, false
	}
	return priv, pub, true
}

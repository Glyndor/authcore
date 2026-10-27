// Package pemcodec converts Ed25519 keys to and from their on-disk PEM form:
// PKCS#8 for the private key, PKIX for the public key, one canonical block per
// file.
package pemcodec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// EncodePrivateKeyPEM serialises an Ed25519 private key into the PKCS#8 PEM
// form written to disk. Exposed so the staging path can build the same bytes
// the existing writer produces, without going through the size-capped reader.
func EncodePrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal Ed25519 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodePublicKeyPEM serialises an Ed25519 public key into the PKIX PEM form
// written to disk.
func EncodePublicKeyPEM(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal Ed25519 public key: %w", err)
	}
	//nolint:gosec // public key is intentionally world-readable
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// DecodeEd25519PrivatePEM parses a PKCS#8 PEM block into an Ed25519 private key.
// src names the origin (a path or "input") for error messages.
func DecodeEd25519PrivatePEM(data []byte, src string) (ed25519.PrivateKey, error) {
	der, err := DecodePEMBlock(data, "PRIVATE KEY", src)
	if err != nil {
		return nil, err
	}
	raw, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key from %q: %w", src, err)
	}
	key, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %q is not an Ed25519 private key (got %T)", src, raw)
	}
	return key, nil
}

// DecodeEd25519PublicPEM parses a PKIX PEM block into an Ed25519 public key.
// src names the origin (a path or "input") for error messages.
func DecodeEd25519PublicPEM(data []byte, src string) (ed25519.PublicKey, error) {
	der, err := DecodePEMBlock(data, "PUBLIC KEY", src)
	if err != nil {
		return nil, err
	}
	raw, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key from %q: %w", src, err)
	}
	key, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %q is not an Ed25519 public key (got %T)", src, raw)
	}
	return key, nil
}

// DecodePEMBlock returns the DER bytes of the one PEM block in data, which
// must be labelled wantType, carry no headers, and be the only thing in data
// apart from whitespace. pem.Decode alone returns the first block wherever
// it sits and ignores the label, the headers and whatever follows, so a file
// holding two keys signed with whichever came first, and a PKCS#8 key under a
// CERTIFICATE label or behind Proc-Type headers was accepted (measured
// 2026-09-25). Key material has one canonical shape here.
func DecodePEMBlock(data []byte, wantType, src string) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, fmt.Errorf("%q does not start with a PEM block", src)
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", src)
	}
	// The decoded block must be the first BEGIN, without a skipped prefix.
	consumed := trimmed[:len(trimmed)-len(rest)]
	if bytes.Count(consumed, []byte("-----BEGIN ")) != 1 {
		return nil, fmt.Errorf("%q holds text before the decoded PEM block", src)
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("PEM block in %q is labelled %q, want %q", src, block.Type, wantType)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("PEM block in %q carries headers; an encrypted or annotated block is not accepted", src)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%q holds more than one PEM block, or text after it", src)
	}
	return block.Bytes, nil
}

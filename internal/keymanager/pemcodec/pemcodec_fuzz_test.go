package pemcodec

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"testing"
)

// seedPEMs adds a valid private and public key and a few near misses.
func seedPEMs(f *testing.F) {
	f.Helper()
	_, _, privPEM, pubPEM := pairFor(f)
	f.Add(privPEM)
	f.Add(pubPEM)
	f.Add(append(append([]byte{}, privPEM...), pubPEM...))
	f.Add(append([]byte("junk\n"), privPEM...))
	f.Add(bytes.ReplaceAll(privPEM, []byte("PRIVATE KEY"), []byte("CERTIFICATE")))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte{})
}

// pairFor builds an Ed25519 pair and its PEM encodings for a fuzz seed.
func pairFor(f *testing.F) (ed25519.PrivateKey, ed25519.PublicKey, []byte, []byte) {
	f.Helper()
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7, 1, 9, 4}, 64)))
	if err != nil {
		f.Fatal(err)
	}
	privPEM, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		f.Fatal(err)
	}
	pubPEM, err := EncodePublicKeyPEM(pub)
	if err != nil {
		f.Fatal(err)
	}
	return priv, pub, privPEM, pubPEM
}

// FuzzDecodePEMBlock drives the canonical-shape check with arbitrary bytes.
// It must never panic, and whatever it accepts must be exactly one block of
// the wanted type, with no headers and nothing after it, whose bytes survive a
// re-encode.
func FuzzDecodePEMBlock(f *testing.F) {
	seedPEMs(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, want := range []string{"PRIVATE KEY", "PUBLIC KEY"} {
			der, err := DecodePEMBlock(data, want, "fuzz")
			if err != nil {
				if der != nil {
					t.Fatal("bytes returned alongside an error")
				}
				continue
			}
			trimmed := bytes.TrimSpace(data)
			block, rest := pem.Decode(trimmed)
			if block == nil || block.Type != want || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
				t.Fatalf("accepted a block that is not one clean %q block: %q", want, data)
			}
			if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
				t.Fatalf("accepted input that does not start with a PEM armour line: %q", data)
			}
			again, err := DecodePEMBlock(pem.EncodeToMemory(&pem.Block{Type: want, Bytes: der}), want, "fuzz")
			if err != nil || !bytes.Equal(again, der) {
				t.Fatalf("the accepted bytes do not survive a re-encode: %v", err)
			}
		}
	})
}

// FuzzDecodeEd25519PEM drives both key decoders. Whatever they accept must be
// a key of exactly the Ed25519 size that round-trips through the encoder, and
// a private key must derive the public half it reports.
func FuzzDecodeEd25519PEM(f *testing.F) {
	seedPEMs(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if priv, err := DecodeEd25519PrivatePEM(data, "fuzz"); err == nil {
			if len(priv) != ed25519.PrivateKeySize {
				t.Fatalf("accepted a %d byte private key", len(priv))
			}
			if !bytes.Equal(ed25519.NewKeyFromSeed(priv.Seed()), priv) {
				t.Fatal("accepted a private key whose halves disagree")
			}
			enc, err := EncodePrivateKeyPEM(priv)
			if err != nil {
				t.Fatal(err)
			}
			back, err := DecodeEd25519PrivatePEM(enc, "fuzz")
			if err != nil || !bytes.Equal(back, priv) {
				t.Fatalf("private key does not round-trip: %v", err)
			}
		}
		if pub, err := DecodeEd25519PublicPEM(data, "fuzz"); err == nil {
			if len(pub) != ed25519.PublicKeySize {
				t.Fatalf("accepted a %d byte public key", len(pub))
			}
			enc, err := EncodePublicKeyPEM(pub)
			if err != nil {
				t.Fatal(err)
			}
			back, err := DecodeEd25519PublicPEM(enc, "fuzz")
			if err != nil || !bytes.Equal(back, pub) {
				t.Fatalf("public key does not round-trip: %v", err)
			}
		}
	})
}

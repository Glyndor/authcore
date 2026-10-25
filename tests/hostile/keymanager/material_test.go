//go:build unix

package hostile

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 6, key material: PEM files that parse but are not an Ed25519 pair.

var (
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidX25519  = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidEd448   = asn1.ObjectIdentifier{1, 3, 101, 113}
)

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type spki struct {
	Algo      pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func mustDER(t testing.TB, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pemOf(label string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
}

// ed25519PKCS8 hand-builds a PKCS#8 structure so a field can be made wrong.
func ed25519PKCS8(t testing.TB, algo pkix.AlgorithmIdentifier, inner []byte) []byte {
	t.Helper()
	return mustDER(t, pkcs8{Version: 0, Algo: algo, PrivateKey: inner})
}

func mustPEMDER(t testing.TB, b []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	return blk.Bytes
}

func octet(t testing.TB, b []byte) []byte {
	t.Helper()
	return mustDER(t, b)
}

var (
	foreignOnce sync.Once
	foreign     struct{ rsaPriv, rsaPub, rsaPKCS1, ecPriv, ecPub, ecSEC1, x25519Priv, x25519Pub []byte }
)

// foreignKeys builds keys of other types once; RSA generation is the slow part.
func foreignKeys(t testing.TB) {
	t.Helper()
	foreignOnce.Do(func() {
		rk, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		xk, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		must := func(b []byte, err error) []byte {
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		foreign.rsaPriv = pemOf("PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(rk)))
		foreign.rsaPub = pemOf("PUBLIC KEY", must(x509.MarshalPKIXPublicKey(&rk.PublicKey)))
		foreign.rsaPKCS1 = pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk))
		foreign.ecPriv = pemOf("PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(ek)))
		foreign.ecPub = pemOf("PUBLIC KEY", must(x509.MarshalPKIXPublicKey(&ek.PublicKey)))
		foreign.ecSEC1 = pemOf("EC PRIVATE KEY", must(x509.MarshalECPrivateKey(ek)))
		foreign.x25519Priv = pemOf("PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(xk)))
		foreign.x25519Pub = pemOf("PUBLIC KEY", must(x509.MarshalPKIXPublicKey(xk.PublicKey())))
	})
}

// hostilePrivate lists private key files that must all be refused.
func hostilePrivate(t *testing.T, s keySet) map[string][]byte {
	t.Helper()
	foreignKeys(t)
	seed := s.priv.Seed()
	ed := pkix.AlgorithmIdentifier{Algorithm: oidEd25519}
	nullParams := pkix.AlgorithmIdentifier{Algorithm: oidEd25519, Parameters: asn1.NullRawValue}
	blk, _ := pem.Decode(s.privPEM)
	two := append(append([]byte{}, s.privPEM...), s.privPEM...)
	return map[string][]byte{
		"RSA PKCS#8":                    foreign.rsaPriv,
		"RSA PKCS#1":                    foreign.rsaPKCS1,
		"ECDSA P-256 PKCS#8":            foreign.ecPriv,
		"ECDSA SEC1":                    foreign.ecSEC1,
		"X25519 PKCS#8":                 foreign.x25519Priv,
		"public key in the private":     s.pubPEM,
		"RSA public in the private":     foreign.rsaPub,
		"seed of 31 bytes":              pemOf("PRIVATE KEY", ed25519PKCS8(t, ed, octet(t, seed[:31]))),
		"seed of 33 bytes":              pemOf("PRIVATE KEY", ed25519PKCS8(t, ed, octet(t, append(append([]byte{}, seed...), 0)))),
		"empty seed":                    pemOf("PRIVATE KEY", ed25519PKCS8(t, ed, octet(t, nil))),
		"64 byte expanded key":          pemOf("PRIVATE KEY", ed25519PKCS8(t, ed, octet(t, s.priv))),
		"seed without octet string":     pemOf("PRIVATE KEY", ed25519PKCS8(t, ed, seed)),
		"NULL parameters on the OID":    pemOf("PRIVATE KEY", ed25519PKCS8(t, nullParams, octet(t, seed))),
		"X25519 OID, ed25519 seed":      pemOf("PRIVATE KEY", ed25519PKCS8(t, pkix.AlgorithmIdentifier{Algorithm: oidX25519}, octet(t, seed))),
		"Ed448 OID, ed25519 seed":       pemOf("PRIVATE KEY", ed25519PKCS8(t, pkix.AlgorithmIdentifier{Algorithm: oidEd448}, octet(t, seed))),
		"unknown OID":                   pemOf("PRIVATE KEY", ed25519PKCS8(t, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}, octet(t, seed))),
		"DER truncated":                 pemOf("PRIVATE KEY", blk.Bytes[:len(blk.Bytes)-3]),
		"wrong label CERTIFICATE":       pemOf("CERTIFICATE", blk.Bytes),
		"wrong label ED25519 PRIVATE":   pemOf("ED25519 PRIVATE KEY", blk.Bytes),
		"lowercase label":               bytes.ReplaceAll(s.privPEM, []byte("PRIVATE KEY"), []byte("private key")),
		"encrypted PKCS#8 label":        pemOf("ENCRYPTED PRIVATE KEY", blk.Bytes),
		"Proc-Type header":              []byte("-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n" + strings.SplitN(string(s.privPEM), "\n", 2)[1]),
		"two blocks":                    two,
		"text before the block":         append([]byte("# comment\n"), s.privPEM...),
		"text after the block":          append(append([]byte{}, s.privPEM...), []byte("trailing\n")...),
		"a second public block":         append(append([]byte{}, s.privPEM...), s.pubPEM...),
		"no END line":                   bytes.SplitN(s.privPEM, []byte("-----END"), 2)[0],
		"bad base64":                    []byte("-----BEGIN PRIVATE KEY-----\n!!!!@@@@####\n-----END PRIVATE KEY-----\n"),
		"empty body":                    []byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"),
		"private key as hex":            []byte(strings.Repeat("ab", 32)),
		"DER without PEM armour":        blk.Bytes,
		"base64 DER without PEM armour": []byte(strings.SplitN(strings.SplitN(string(s.privPEM), "\n", 2)[1], "-----END", 2)[0]),
	}
}

// hostilePublic lists public key files that must all be refused.
func hostilePublic(t *testing.T, s keySet) map[string][]byte {
	t.Helper()
	foreignKeys(t)
	ed := pkix.AlgorithmIdentifier{Algorithm: oidEd25519}
	blk, _ := pem.Decode(s.pubPEM)
	bits := func(b []byte) asn1.BitString { return asn1.BitString{Bytes: b, BitLength: len(b) * 8} }
	return map[string][]byte{
		"RSA public":                 foreign.rsaPub,
		"ECDSA public":               foreign.ecPub,
		"X25519 public":              foreign.x25519Pub,
		"private key in the public":  s.privPEM,
		"31 byte point":              pemOf("PUBLIC KEY", mustDER(t, spki{ed, bits(s.pub[:31])})),
		"33 byte point":              pemOf("PUBLIC KEY", mustDER(t, spki{ed, bits(append(append([]byte{}, s.pub...), 0))})),
		"empty point":                pemOf("PUBLIC KEY", mustDER(t, spki{ed, bits(nil)})),
		"NULL parameters on the OID": pemOf("PUBLIC KEY", mustDER(t, spki{pkix.AlgorithmIdentifier{Algorithm: oidEd25519, Parameters: asn1.NullRawValue}, bits(s.pub)})),
		"X25519 OID":                 pemOf("PUBLIC KEY", mustDER(t, spki{pkix.AlgorithmIdentifier{Algorithm: oidX25519}, bits(s.pub)})),
		"Ed448 OID":                  pemOf("PUBLIC KEY", mustDER(t, spki{pkix.AlgorithmIdentifier{Algorithm: oidEd448}, bits(s.pub)})),
		"wrong label":                pemOf("CERTIFICATE", blk.Bytes),
		"RSA PUBLIC KEY label":       pemOf("RSA PUBLIC KEY", blk.Bytes),
		"two blocks":                 append(append([]byte{}, s.pubPEM...), s.pubPEM...),
		"text after":                 append(append([]byte{}, s.pubPEM...), []byte("x")...),
		"header":                     []byte("-----BEGIN PUBLIC KEY-----\nX-Note: hi\n\n" + strings.SplitN(string(s.pubPEM), "\n", 2)[1]),
		"DER trailing bytes":         pemOf("PUBLIC KEY", append(append([]byte{}, blk.Bytes...), 1)),
		"another set's public key":   newSet(t).pubPEM,
		"all-zero point":             pemOf("PUBLIC KEY", mustDER(t, spki{ed, bits(make([]byte, 32))})),
	}
}

func TestHostile_Material_hostilePrivateKeyFilesAreRefusedAndKept(t *testing.T) {
	s := newSet(t)
	for name, content := range hostilePrivate(t, s) {
		t.Run(name, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				dir := sb.withSet(t, s)
				put(t, filepath.Join(dir, layout.FilePrivateKey), content, 0o600)
				before := keyTree(t, dir)

				refused(t, open(t, dir, loadOnly), s)

				assertSame(t, "KeysDir", before, keyTree(t, dir))
			})
		})
	}
}

func TestHostile_Material_hostilePublicKeyFilesAreRefusedAndKept(t *testing.T) {
	s := newSet(t)
	for name, content := range hostilePublic(t, s) {
		t.Run(name, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				dir := sb.withSet(t, s)
				put(t, filepath.Join(dir, layout.FilePublicKey), content, 0o644)
				before := keyTree(t, dir)

				refused(t, open(t, dir, loadOnly), s)

				assertSame(t, "KeysDir", before, keyTree(t, dir))
			})
		})
	}
}

func TestHostile_Material_validButUnusualEncodingsStillLoad(t *testing.T) {
	s := newSet(t)
	crlf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }
	cases := map[string][2][]byte{
		"CRLF line endings":   {crlf(s.privPEM), crlf(s.pubPEM)},
		"blank lines around":  {append(append([]byte("\n\n"), s.privPEM...), '\n', '\n'), append(append([]byte("\n"), s.pubPEM...), ' ', '\n')},
		"no trailing newline": {bytes.TrimSpace(s.privPEM), bytes.TrimSpace(s.pubPEM)},
		// The standard library parser ignores bytes after the DER structure and
		// the PKCS#8 version number. Neither changes which key is loaded, which is
		// what this pins: leniency about encoding must never alter the material.
		"PKCS#8 version 7":         {pemOf("PRIVATE KEY", mustDER(t, pkcs8{Version: 7, Algo: pkix.AlgorithmIdentifier{Algorithm: oidEd25519}, PrivateKey: octet(t, s.priv.Seed())})), s.pubPEM},
		"private DER with trailer": {pemOf("PRIVATE KEY", append(append([]byte{}, mustPEMDER(t, s.privPEM)...), 0, 0, 0)), s.pubPEM},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			dir := sb.withSet(t, s)
			put(t, filepath.Join(dir, layout.FilePrivateKey), c[0], 0o600)
			put(t, filepath.Join(dir, layout.FilePublicKey), c[1], 0o644)
			loaded(t, open(t, dir, true), s)
		})
	}
}

func TestHostile_Material_publicAndPrivateFromDifferentSetsAreRefused(t *testing.T) {
	a, b := newSet(t), newSet(t)
	cases := map[string]func(dir string){
		"public from another set": func(dir string) { put(t, filepath.Join(dir, layout.FilePublicKey), b.pubPEM, 0o644) },
		"private from another set": func(dir string) {
			put(t, filepath.Join(dir, layout.FilePrivateKey), b.privPEM, 0o600)
		},
		"files swapped": func(dir string) {
			put(t, filepath.Join(dir, layout.FilePrivateKey), a.pubPEM, 0o600)
			put(t, filepath.Join(dir, layout.FilePublicKey), a.privPEM, 0o644)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				dir := sb.withSet(t, a)
				mutate(dir)
				before := keyTree(t, dir)

				refused(t, open(t, dir, loadOnly), a, b)

				assertSame(t, "KeysDir", before, keyTree(t, dir))
			})
		})
	}
}

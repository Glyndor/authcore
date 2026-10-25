//go:build unix

package hostile

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// Class 12: public keys that are valid encodings of points no honest key pair
// produces. A verifier that accepted one beside the real private key would
// check signatures against a point of small order, for which many messages
// verify. The pair check compares the file with the key derived from the
// private seed, so each of these must be refused by both modes and the files
// left exactly as found.

// smallOrderPoints are the Ed25519 points of order 1, 2, 4 and 8 in their
// canonical little-endian encodings, with the sign bit set and clear.
var smallOrderPoints = map[string]string{
	"order 1, identity":             "0100000000000000000000000000000000000000000000000000000000000000",
	"order 2":                       "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"order 4, positive x":           "0000000000000000000000000000000000000000000000000000000000000000",
	"order 4, negative x":           "0000000000000000000000000000000000000000000000000000000000000080",
	"order 8, first":                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"order 8, first, sign flipped":  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"order 8, second":               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"order 8, second, sign flipped": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	// y = p and y = p+1 reduce to the points of order 4 and 1, but are not the
	// canonical encoding of either.
	"non-canonical y = p":     "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"non-canonical y = p + 1": "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"all ones":                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestHostile_Curve_smallOrderAndNonCanonicalPublicKeysAreRefused(t *testing.T) {
	for name, enc := range smallOrderPoints {
		raw, err := hex.DecodeString(enc)
		if err != nil || len(raw) != 32 {
			t.Fatalf("bad fixture %q: %v", name, err)
		}
		pubPEM, err := pemcodec.EncodePublicKeyPEM(raw)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(name, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				s := newSet(t)
				dir := sb.withSet(t, s)
				put(t, filepath.Join(dir, layout.FilePublicKey), pubPEM, 0o644)
				before := keyFileBytes(t, dir)

				refused(t, open(t, dir, loadOnly), s)

				if after := keyFileBytes(t, dir); after != before {
					t.Error("a refused start changed a key file")
				}
			})
		})
	}
}

// The honest key with its sign bit flipped is the negated point: a valid curve
// point, not the key the seed derives.
func TestHostile_Curve_negatedPublicKeyIsRefused(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		s := newSet(t)
		dir := sb.withSet(t, s)
		negated := append([]byte(nil), s.pub...)
		negated[31] ^= 0x80
		pubPEM, err := pemcodec.EncodePublicKeyPEM(negated)
		if err != nil {
			t.Fatal(err)
		}
		put(t, filepath.Join(dir, layout.FilePublicKey), pubPEM, 0o644)

		refused(t, open(t, dir, loadOnly), s)
	})
}

// keyFileBytes concatenates the three key files, so a refused start can be
// shown not to have rewritten any of them (New may still add its .gitignore).
func keyFileBytes(t testing.TB, dir string) string {
	t.Helper()
	var all []byte
	for _, n := range layout.KeyFileNames() {
		all = append(append(all, n...), read(t, filepath.Join(dir, n))...)
	}
	return string(all)
}

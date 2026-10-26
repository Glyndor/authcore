//go:build unix

package filetypes

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// FuzzOpenWithHostileFile replaces one file of a valid KeysDir with arbitrary
// bytes and starts a key manager over it, in both modes. The directory is
// complete, so the only outcomes allowed are an error or the original key pair;
// a hostile file must never be loaded as a different key, never make the start
// panic or hang, never be rewritten by the load-only path and never be echoed
// into the error or the log.
func FuzzOpenWithHostileFile(f *testing.F) {
	owner, other := hostiletest.NewSet(f), hostiletest.NewSet(f)
	names := append(layout.KeyFileNames(), layout.FileMetadata, layout.FileGitignore)
	seeds := [][]byte{
		nil, []byte("\n"), owner.PrivPEM, owner.PubPEM, owner.SecretHex,
		[]byte(`{"format":1}`), []byte(`{"format":9}`), bytes.Repeat([]byte("A"), layout.MaxKeyFileSize+1),
		[]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"),
		other.PrivPEM, other.PubPEM, other.SecretHex,
	}
	for i := range names {
		for _, seed := range seeds {
			f.Add(uint8(i), seed)
		}
	}

	f.Fuzz(func(t *testing.T, which uint8, content []byte) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.WithSet(t, owner)
		name := names[int(which)%len(names)]
		hostiletest.Put(t, filepath.Join(dir, name), content, 0o600)
		secretNeedles := owner.Needles()

		for _, loadOnly := range []bool{true, false} {
			before := hostiletest.KeyTree(t, dir)
			r := hostiletest.Open(t, dir, loadOnly)
			if r.Err != nil {
				for _, n := range secretNeedles {
					if len(content) < len(n) && bytes.Contains([]byte(r.Err.Error()+r.Log.All()), []byte(n)) {
						t.Fatalf("an error or log line carries key material of the owner: %.20s", n)
					}
				}
				if loadOnly {
					hostiletest.AssertSame(t, "KeysDir after a refused load-only start", before, hostiletest.KeyTree(t, dir))
				}
				continue
			}
			if !bytes.Equal(r.Keys.PublicKey(), r.Keys.PrivateKey().Public().(ed25519.PublicKey)) {
				t.Fatalf("loaded a public key that is not the public half of the private key after %s was replaced", name)
			}
			if !bytes.Equal(r.Keys.PrivateKey(), owner.Priv) && name != layout.FilePrivateKey {
				t.Fatalf("loaded another private key after %s was replaced", name)
			}
			if !bytes.Equal(r.Keys.RefreshSecret(), owner.Secret) && name != layout.FileRefreshSecret {
				t.Fatalf("loaded another refresh secret after %s was replaced", name)
			}
		}
	})
}

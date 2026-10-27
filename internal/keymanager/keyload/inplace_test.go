package keyload

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// rewriteInPlace overwrites every key file of dir with the bytes of the same
// file in from. WriteFile truncates the existing file, so each path keeps its
// inode: only the content changes.
func rewriteInPlace(t *testing.T, dir, from string) {
	t.Helper()
	for _, name := range layout.KeyFileNames() {
		path := filepath.Join(dir, name)
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(from, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, before.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) {
			t.Fatal("fixture replaced an inode")
		}
	}
}

// isWholeSet reports whether the loaded material is exactly one written set.
func isWholeSet(set keyloadtest.KeySet, priv, pub, secret []byte) bool {
	return bytes.Equal(priv, set.Priv) && bytes.Equal(pub, set.Pub) && bytes.Equal(secret, set.Secret)
}

func TestFiles_InPlaceRewriteNeverReturnsMixedKeyMaterial(t *testing.T) {
	dir, replacementDir := t.TempDir(), t.TempDir()
	first := keyloadtest.WriteSet(t, dir)
	second := keyloadtest.WriteSet(t, replacementDir)
	priv, pub, secret, err := Files(dir, keyloadtest.SilentLog{})
	if err != nil || !isWholeSet(first, priv, pub, secret) {
		t.Fatalf("control: unchanged set did not round trip: %v", err)
	}
	rewritten := false
	hooks(t, func(attempt, file int) {
		if attempt == 0 && file == 1 {
			rewriteInPlace(t, dir, replacementDir)
			rewritten = true
		}
	})
	priv, pub, secret, err = Files(dir, keyloadtest.SilentLog{})
	if !rewritten {
		t.Fatal("fixture never rewrote the set during loading")
	}
	if err != nil {
		return
	}
	if !isWholeSet(first, priv, pub, secret) && !isWholeSet(second, priv, pub, secret) {
		t.Fatal("load returned key material from different sets")
	}
}

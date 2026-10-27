package keyload

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestFiles_InPlaceRewriteNeverReturnsMixedKeyMaterial(t *testing.T) {
	dir, replacementDir := t.TempDir(), t.TempDir()
	first := keyloadtest.WriteSet(t, dir)
	second := keyloadtest.WriteSet(t, replacementDir)
	priv, pub, secret, err := Files(dir, keyloadtest.SilentLog{})
	if err != nil || !priv.Equal(first.Priv) || !pub.Equal(first.Pub) || !bytes.Equal(secret, first.Secret) {
		t.Fatalf("control: unchanged set did not round trip: %v", err)
	}
	rewritten := false
	hooks(t, func(attempt, file int) {
		if attempt != 0 || file != 1 {
			return
		}
		for _, name := range layout.KeyFileNames() {
			path := filepath.Join(dir, name)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(replacementDir, name))
			if err != nil {
				t.Fatal(err)
			}
			// WriteFile truncates the existing file; the path must retain its inode.
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
		rewritten = true
	})
	priv, pub, secret, err = Files(dir, keyloadtest.SilentLog{})
	if !rewritten {
		t.Fatal("fixture never rewrote the set during loading")
	}
	if err != nil {
		return
	}
	wholeFirst := priv.Equal(first.Priv) && pub.Equal(first.Pub) && bytes.Equal(secret, first.Secret)
	wholeSecond := priv.Equal(second.Priv) && pub.Equal(second.Pub) && bytes.Equal(secret, second.Secret)
	if !wholeFirst && !wholeSecond {
		t.Fatal("load returned key material from different sets")
	}
}

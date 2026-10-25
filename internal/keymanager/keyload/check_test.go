package keyload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestCheck_acceptsAConsistentSet(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	if err := Check(dir); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheck_refusesAnInconsistentSet(t *testing.T) {
	other := t.TempDir()
	keyloadtest.WriteSet(t, other)

	for name, tc := range map[string]struct {
		break_ func(t *testing.T, dir string)
		want   string
	}{
		"public key of another set": {func(t *testing.T, dir string) {
			data, err := os.ReadFile(filepath.Join(other, layout.FilePublicKey))
			if err != nil {
				t.Fatal(err)
			}
			keyloadtest.Put(t, dir, layout.FilePublicKey, data, 0644)
		}, "does not match private key"},
		"missing secret": {func(t *testing.T, dir string) {
			_ = os.Remove(filepath.Join(dir, layout.FileRefreshSecret))
		}, "refresh secret"},
		"short secret": {func(t *testing.T, dir string) {
			keyloadtest.Put(t, dir, layout.FileRefreshSecret, []byte("abcd\n"), 0600)
		}, "wrong length"},
		"corrupt private key": {func(t *testing.T, dir string) {
			keyloadtest.Put(t, dir, layout.FilePrivateKey, []byte("junk"), 0600)
		}, "ed25519 key pair"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			keyloadtest.WriteSet(t, dir)
			tc.break_(t, dir)
			if err := Check(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Check = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

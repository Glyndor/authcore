package match

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// FuzzFindStaging drives staging discovery with arbitrary directory-entry
// names and arbitrary staged private-key bytes. It must never panic, must
// only ever answer with a directory directly inside dir whose name carries
// the staging prefix, and may adopt one only when the staged private key
// equals the published one (or none is published) and the staged files form a
// valid key set. The staged public key and secret here are filler, so no
// input may be adopted at all.
func FuzzFindStaging(f *testing.F) {
	f.Add("abcdef0123456789", []byte("key"), []byte("key"), true)
	f.Add("..", []byte("a"), []byte("b"), true)
	f.Add("x\n[ERROR] forged", []byte("a"), []byte("a"), true)
	f.Add("\xff\xfe", []byte{}, []byte{}, false)
	f.Add(strings.Repeat("n", 200), []byte("k"), []byte("k"), true)

	f.Fuzz(func(t *testing.T, suffix string, stagedPriv, publishedPriv []byte, published bool) {
		if strings.ContainsAny(suffix, "/\x00") || len(layout.StagingPrefix+suffix) > 255 {
			t.Skip("not a valid directory entry name")
		}
		if len(stagedPriv) > layout.MaxKeyFileSize || len(publishedPriv) > layout.MaxKeyFileSize {
			t.Skip("over the read cap, covered by the cap tests")
		}
		if runtime.GOOS == "windows" && (!utf8.ValidString(suffix) || strings.HasSuffix(suffix, ".") || strings.HasSuffix(suffix, " ") || strings.ContainsAny(suffix, `<>:"|?*\`)) {
			t.Skip("Windows rewrites or refuses this directory name, so the entry the test creates is not the one it names")
		}
		dir := t.TempDir()
		staging := filepath.Join(dir, layout.StagingPrefix+suffix)
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Skipf("filesystem refuses the name: %v", err)
		}
		for _, name := range layout.KeyFileNames() {
			data := []byte("x")
			if name == layout.FilePrivateKey {
				data = stagedPriv
			}
			if err := os.WriteFile(filepath.Join(staging, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if published {
			if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), publishedPriv, 0o600); err != nil {
				t.Fatal(err)
			}
		}

		got, err := FindStaging(dir)
		if err != nil {
			if !errors.Is(err, ErrNoMatchingStaging) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		t.Fatalf("adopted a staging directory that is not a valid key set: %q", got)
	})
}

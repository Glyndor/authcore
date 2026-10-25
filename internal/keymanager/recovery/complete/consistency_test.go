package complete

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/match"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// A staged set whose public key or secret is not the set's own is refused
// before any of its files is linked into the key directory.
func TestFromStaging_linksNothingFromAnInconsistentSet(t *testing.T) {
	recoverytest.PosixOnly(t)
	for _, swap := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		t.Run(swap, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "keys")
			mine := recoverytest.MustSeed(t, filepath.Join(base, "mine"))
			foreign := recoverytest.MustSeed(t, filepath.Join(base, "foreign"))
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			recoverytest.CopyFile(t, filepath.Join(mine, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
			staging := recoverytest.StagingFrom(t, dir, "x", mine)
			recoverytest.CopyFile(t, filepath.Join(foreign, swap), filepath.Join(staging, swap))
			if swap == layout.FileRefreshSecret {
				// A well-formed secret is consistent by itself; make it invalid.
				if err := os.WriteFile(filepath.Join(staging, swap), []byte("short\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			err := FromStaging(dir, staging)

			if !errors.Is(err, match.ErrNoMatchingStaging) {
				t.Fatalf("FromStaging = %v, want match.ErrNoMatchingStaging", err)
			}
			for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
				if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
					t.Errorf("%s was linked from an inconsistent staged set", n)
				}
			}
		})
	}
}

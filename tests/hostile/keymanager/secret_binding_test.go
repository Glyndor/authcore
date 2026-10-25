//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// A refresh secret that does not belong to the recorded key pair must stop
// the start, in both the writable and the load-only mode.
func TestHostile_SecretOfAnotherSetIsRefused(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		a, b := newSet(t), newSet(t)
		dir := sb.withSet(t, a)
		loaded(t, open(t, dir, false), a)
		put(t, filepath.Join(dir, layout.FileRefreshSecret), b.secretHex, 0o600)

		refused(t, open(t, dir, loadOnly), a, b)
	})
}

// A set recorded before the binding existed keeps loading with the same keys,
// is bound in place on the first start, and is checked from then on.
func TestHostile_SetWithoutBindingIsBoundInPlace(t *testing.T) {
	sb := newSandbox(t)
	a, b := newSet(t), newSet(t)
	dir := sb.withSet(t, a)
	meta := filepath.Join(dir, layout.FileMetadata)
	put(t, meta, []byte(`{"format":1,"created":"2026-01-01T00:00:00Z","key_id":"`+a.keyID()+`"}`+"\n"), 0o600)

	first := open(t, dir, false)
	loaded(t, first, a)
	if !first.log.has("binding") {
		t.Errorf("the migration was not reported: %s", first.log.all())
	}
	bound := read(t, meta)

	second := open(t, dir, false)
	loaded(t, second, a)
	if got := read(t, meta); string(got) != string(bound) {
		t.Errorf("a bound set was rewritten on the next start:\n%s\n%s", bound, got)
	}

	put(t, filepath.Join(dir, layout.FileRefreshSecret), b.secretHex, 0o600)
	refused(t, open(t, dir, false), a, b)
}

// A directory with no metadata at all (the oldest layout) also migrates.
func TestHostile_SetWithoutMetadataIsBoundOnFirstStart(t *testing.T) {
	sb := newSandbox(t)
	a := newSet(t)
	dir := sb.withSet(t, a)

	loaded(t, open(t, dir, false), a)
	if _, err := os.Stat(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}
	loaded(t, open(t, dir, true), a)
}

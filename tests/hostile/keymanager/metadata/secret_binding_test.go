//go:build unix

package metadata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// A refresh secret that does not belong to the recorded key pair must stop
// the start, in both the writable and the load-only mode.
func TestHostile_SecretOfAnotherSetIsRefused(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		a, b := hostiletest.NewSet(t), hostiletest.NewSet(t)
		dir := sb.WithSet(t, a)
		hostiletest.Loaded(t, hostiletest.Open(t, dir, false), a)
		hostiletest.Put(t, filepath.Join(dir, layout.FileRefreshSecret), b.SecretHex, 0o600)

		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), a, b)
	})
}

// A set recorded before the binding existed keeps loading with the same keys,
// is bound in place on the first start, and is checked from then on.
func TestHostile_SetWithoutBindingIsBoundInPlace(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	a, b := hostiletest.NewSet(t), hostiletest.NewSet(t)
	dir := sb.WithSet(t, a)
	meta := filepath.Join(dir, layout.FileMetadata)
	hostiletest.Put(t, meta, []byte(`{"format":1,"created":"2026-01-01T00:00:00Z","key_id":"`+a.KeyID()+`"}`+"\n"), 0o600)

	first := hostiletest.Open(t, dir, false)
	hostiletest.Loaded(t, first, a)
	if !first.Log.Has("binding") {
		t.Errorf("the migration was not reported: %s", first.Log.All())
	}
	bound := hostiletest.Read(t, meta)

	second := hostiletest.Open(t, dir, false)
	hostiletest.Loaded(t, second, a)
	if got := hostiletest.Read(t, meta); string(got) != string(bound) {
		t.Errorf("a bound set was rewritten on the next start:\n%s\n%s", bound, got)
	}

	hostiletest.Put(t, filepath.Join(dir, layout.FileRefreshSecret), b.SecretHex, 0o600)
	hostiletest.Refused(t, hostiletest.Open(t, dir, false), a, b)
}

// A directory with no metadata at all (the oldest layout) also migrates.
func TestHostile_SetWithoutMetadataIsBoundOnFirstStart(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	a := hostiletest.NewSet(t)
	dir := sb.WithSet(t, a)

	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), a)
	if _, err := os.Stat(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}
	hostiletest.Loaded(t, hostiletest.Open(t, dir, true), a)
}

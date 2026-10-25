package layout_test

import (
	"slices"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestKeyFileNames_fixedOrder(t *testing.T) {
	want := []string{"ed25519_private.pem", "ed25519_public.pem", "refresh_secret.key"}
	if got := layout.KeyFileNames(); !slices.Equal(got, want) {
		t.Fatalf("KeyFileNames() = %v, want %v", got, want)
	}
}

func TestKeyFileNames_returnsAFreshSlice(t *testing.T) {
	a := layout.KeyFileNames()
	a[0] = "tampered"
	if b := layout.KeyFileNames(); b[0] != layout.FilePrivateKey {
		t.Fatalf("mutating one result changed the next: %q", b[0])
	}
}

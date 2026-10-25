package credential_test

import (
	"testing"

	"github.com/Glyndor/authcore/auth/credential"
)

// newModuleWith builds a module over a pepper the test keeps, so an oracle can
// recompute what the module should have produced.
func newModuleWith(t testing.TB, pepper []byte, cfg ...credential.Config) *credential.Credential {
	t.Helper()
	m, err := credential.New(newProviderWithPepper(t, pepper), cfg...)
	if err != nil {
		t.Fatalf("credential.New: %v", err)
	}
	return m
}

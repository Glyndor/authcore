package leak

import (
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// A caller that clears the secret it read, as the wipe-after-use pattern
// does, must not change the secret a module built afterwards gets. Before,
// the accessor returned the slice the key manager holds, so a later
// apikey.New hashed with the cleared bytes and verified nothing the first
// module had issued, without returning an error.
func TestHostile_Leak_clearingTheSecretDoesNotPoisonLaterModules(t *testing.T) {
	e := hostiletest.NewEnv(t)
	first, err := apikey.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	key, err := first.Generate()
	if err != nil {
		t.Fatal(err)
	}

	keys := e.AC.Keys()
	overwrite(keys.RefreshSecret())
	overwrite(keys.PrivateKey())
	overwrite(keys.PublicKey())

	later, err := apikey.New(e.AC)
	if err != nil {
		t.Fatalf("apikey.New after the caller cleared the secret: %v", err)
	}
	if !later.Verify(key.Key, key.Hash) {
		t.Error("a module built after the caller cleared the secret cannot verify a key the first one issued")
	}
}

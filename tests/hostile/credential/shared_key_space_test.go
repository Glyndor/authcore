package credential_test

import (
	"encoding/binary"
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
)

// Contract, documented in docs/modules/credential.md and docs/modules/apikey.md:
// credential hashes and API-key hashes are HMAC-SHA256 under the same managed
// secret, with no label saying which module produced them. They are one key
// space. The input of one module can be shaped like the other's framing, so a
// value stored as a credential hash is also what apikey.Hash gives for that
// framing, and the reverse.
//
// The hashes are not changed, because every stored one would stop matching,
// but apikey.Verify refuses a key that does not have the generated shape.
// This test pins the behaviour so a change to it is a deliberate one, and so
// the advice in the documentation (keep the two kinds of hash in separate
// columns, never compare across them) stays tied to a fact.
func TestHostile_Contract_apiKeyAndCredentialHashesShareOneKeySpace(t *testing.T) {
	pepper := randomPepper(t)
	cred := newModuleWith(t, pepper)
	keysModule, err := apikey.New(newProviderWithPepper(t, pepper))
	if err != nil {
		t.Fatal(err)
	}

	issued, err := cred.Issue("reset", "alice")
	if err != nil {
		t.Fatal(err)
	}

	framed := func(fields ...string) string {
		var b []byte
		for _, f := range fields {
			b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
			b = append(b, f...)
		}
		return string(b)
	}
	got, err := keysModule.Hash(framed("reset", "alice", issued.Token))
	if err != nil {
		t.Fatal(err)
	}
	if got != issued.Hash {
		t.Errorf("the two modules no longer hash into one key space: apikey gave %s, credential stored %s", got, issued.Hash)
	}
	if keysModule.Verify(framed("reset", "alice", issued.Token), issued.Hash) {
		t.Error("apikey.Verify accepted the credential-framed input against the credential's stored hash")
	}

	// Under a different secret the same input gives a different hash: the
	// shared space is per deployment, not global.
	other, err := apikey.New(newProviderWithPepper(t, randomPepper(t)))
	if err != nil {
		t.Fatal(err)
	}
	if h, err := other.Hash(framed("reset", "alice", issued.Token)); err != nil || h == issued.Hash {
		t.Errorf("a different secret produced the same hash (err=%v)", err)
	}
}

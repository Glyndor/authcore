// Package keyspace attacks the modules that hash into one key space: API keys,
// credential tokens, refresh tokens and recovery codes are all HMAC-SHA256
// under the deployment's managed secret, with no label saying which module
// made the hash (docs/modules/apikey.md and docs/modules/credential.md). The
// documented contract is that an application keeps them in separate tables and
// never compares across them. These tests build the careless table and the
// sanctioned ones, and check where the line between them actually falls.
package keyspace

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// kinds of secret a hash column may hold.
const (
	kindAPIKey     = "apikey"
	kindCredential = "credential"
	kindRefresh    = "refresh"
	kindRecovery   = "recovery"
)

// careless is the table the documentation says not to build: one column of
// hashes, a kind column to tell them apart, and a lookup by hash alone.
type careless map[string]string // hash -> kind

// world is one deployment with one module of each kind.
type world struct {
	env  *hostiletest.Env
	keys interface {
		Hash(string) (string, error)
		Verify(string, string) bool
	}
	cred *credential.Credential
	jwt  *jwt.JWT[hostiletest.Extra]
	mfa  *totp.TOTP
}

func newWorld(t *testing.T) *world {
	t.Helper()
	e := hostiletest.NewEnv(t)
	return &world{
		env:  e,
		keys: e.APIKey(t),
		cred: e.Credential(t, credential.Config{TTL: time.Hour}),
		jwt:  e.JWT(t, jwt.Config{}),
		mfa:  e.TOTP(t, totp.Config{}),
	}
}

func frame(fields ...string) string {
	var b []byte
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return string(b)
}

// The documented fact, pinned from the application's side: in a table that
// looks up by hash alone, a value of one kind can be presented as another and
// the lookup lands on the other kind's row. The library compares nothing across
// modules, so nothing in it stops this; the kind column does, if the
// application checks it. Each crossing below needs the attacker to supply the
// exact bytes the other module hashed, which the sanctioned flows never let it
// do.
func TestE2E_Keyspace_aHashColumnWithoutAKindCheckConfusesTheKinds(t *testing.T) {
	w := newWorld(t)
	apiKey := w.env.APIKey(t)
	gen, err := apiKey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := w.jwt.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	issued, _ := w.cred.Issue("reset", "alice")
	enr, _ := w.mfa.Enroll("alice@example.com")

	table := careless{
		gen.Hash: kindAPIKey, pair.RefreshTokenHash: kindRefresh, issued.Hash: kindCredential, enr.RecoveryHashes[0]: kindRecovery,
	}
	lookup := func(presented string) string {
		h, _ := w.keys.Hash(presented)
		return table[h]
	}

	// A refresh token, an API key, a framed credential and a normalized
	// recovery code each hash onto their own row...
	for presented, want := range map[string]string{
		gen.Key:                               kindAPIKey,
		pair.RefreshToken:                     kindRefresh,
		frame("reset", "alice", issued.Token): kindCredential,
		strings.ReplaceAll(enr.RecoveryCodes[0], "-", ""): kindRecovery,
	} {
		if got := lookup(presented); got != want {
			t.Errorf("bare-hash lookup of a %s value landed on %q", want, got)
		}
	}
	// ...which is the confusion the documentation forbids relying on: the jwt
	// module accepts an API key against the stored key. The apikey module no
	// longer reads a refresh hash, because Verify demands the shape it generates.
	if w.keys.Verify(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Error("contract changed: apikey.Verify reads a refresh hash again")
	}
	if !w.jwt.VerifyRefreshTokenHash(gen.Key, gen.Hash) {
		t.Error("contract changed: VerifyRefreshTokenHash no longer reads an API key hash")
	}
}

// The sanctioned shape: one table per kind, each looked up the way its module
// documents. Under it every crossing is refused, for every ordered pair of
// kinds, because each lookup demands the shape of its own kind first.
func TestE2E_Keyspace_separateTablesRefuseEveryCrossing(t *testing.T) {
	w := newWorld(t)
	apiKey := w.env.APIKey(t)
	gen, _ := apiKey.Generate()
	pair, _ := w.jwt.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	issued, _ := w.cred.Issue("reset", "alice")
	enr, _ := w.mfa.Enroll("alice@example.com")
	issuedAt := time.Now()

	apiKeys := map[string]string{gen.ID: gen.Hash} // by id, the documented lookup
	sessions := map[string]string{pair.SessionID: pair.RefreshTokenHash}
	presentAsAPIKey := func(v string) bool {
		id, err := apiKey.ParseID(v)
		if err != nil {
			return false
		}
		stored, ok := apiKeys[id]
		return ok && apiKey.Verify(v, stored)
	}
	presentAsRefresh := func(v string) bool {
		if _, err := w.jwt.RotateTokens(v, hostiletest.Extra{}); err != nil {
			return false
		}
		return w.jwt.VerifyRefreshTokenHash(v, sessions[pair.SessionID])
	}
	presentAsCredential := func(v string) bool {
		return w.cred.Verify("reset", "alice", v, issued.Hash, issuedAt) == nil
	}
	presentAsRecovery := func(v string) bool {
		_, ok := w.mfa.VerifyRecoveryCode(v, enr.RecoveryHashes)
		return ok
	}

	values := map[string]string{
		kindAPIKey: gen.Key, kindRefresh: pair.RefreshToken, kindCredential: issued.Token, kindRecovery: enr.RecoveryCodes[0],
		"access token": pair.AccessToken,
		"framed":       frame("reset", "alice", issued.Token),
		"normalized":   strings.ReplaceAll(enr.RecoveryCodes[0], "-", ""),
	}
	endpoints := map[string]struct {
		accepts func(string) bool
		own     string
	}{
		kindAPIKey: {presentAsAPIKey, kindAPIKey}, kindRefresh: {presentAsRefresh, kindRefresh},
		kindCredential: {presentAsCredential, kindCredential}, kindRecovery: {presentAsRecovery, kindRecovery},
	}
	for endpoint, ep := range endpoints {
		for name, v := range values {
			got := ep.accepts(v)
			want := name == ep.own || (ep.own == kindRecovery && name == "normalized") // same code, spelt without the hyphen
			if got != want {
				t.Errorf("%s endpoint given the %s value: accepted=%v, want %v", endpoint, name, got, want)
			}
		}
	}
}

// A second deployment (another managed secret) shares no hash with this one for
// any input, framed to look like any kind.
func TestE2E_Keyspace_anotherDeploymentSharesNoHash(t *testing.T) {
	a, b := newWorld(t), newWorld(t)
	inputs := []string{"ak_x", frame("reset", "alice", "t"), "ABCD1234EFGH5678", "header.payload.signature", ""}
	for _, in := range inputs {
		ha, _ := a.keys.Hash(in)
		hb, _ := b.keys.Hash(in)
		if ha == hb {
			t.Errorf("two deployments hashed %q alike", in)
		}
		if b.keys.Verify(in, ha) {
			t.Errorf("deployment B verified a hash made by deployment A for %q", in)
		}
	}
	pair, _ := a.jwt.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if b.jwt.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Error("deployment B verified A's refresh hash")
	}
	if _, err := b.jwt.RotateTokens(pair.RefreshToken, hostiletest.Extra{}); !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Errorf("deployment B rotating A's refresh token: %v; want ErrTokenInvalid", err)
	}
}

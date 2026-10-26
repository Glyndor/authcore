package leak

import (
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

func overwrite(b []byte) {
	for i := range b {
		b[i] = 0xAA
	}
}

// A caller that clears the key slices it was handed after reading them must
// not break the modules that were already built from them: each module keeps
// its own copy of what it needs.
func TestHostile_Leak_modulesKeepTheirOwnCopyOfTheKeys(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, err := jwt.New[struct{}](e.AC)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := totp.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := apikey.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := credential.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := field.New(e.AC, field.Config{Context: "users.email"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := cr.Issue("reset", hostiletest.Subject)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := fd.Encrypt("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ak.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, err := tp.HashRecoveryCode("abcde-12345")
	if err != nil {
		t.Fatal(err)
	}

	keys := e.AC.Keys()
	overwrite(keys.PrivateKey())
	overwrite(keys.PublicKey())
	overwrite(keys.RefreshSecret())

	pair, err := j.CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens after the caller cleared the keys: %v", err)
	}
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("VerifyAccessToken after the caller cleared the keys: %v", err)
	}
	if err := cr.Verify("reset", hostiletest.Subject, issued.Token, issued.Hash, time.Now()); err != nil {
		t.Errorf("credential.Verify after the caller cleared the keys: %v", err)
	}
	if got, err := fd.Decrypt(sealed); err != nil || got != "ana@example.com" {
		t.Errorf("field.Decrypt after the caller cleared the keys: %q, %v", got, err)
	}
	if !ak.Verify(key.Key, key.Hash) {
		t.Error("apikey.Verify after the caller cleared the keys")
	}
	if _, ok := tp.VerifyRecoveryCode("abcde-12345", []string{code}); !ok {
		t.Error("totp.VerifyRecoveryCode after the caller cleared the keys")
	}
}

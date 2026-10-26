package leak

import (
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

const (
	subject   = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"
	plaintext = "Correct-Horse-9-Battery-Staple"
	fieldText = "ana.private@example.com"
)

// A developer who turns logs on in production reads them with a wider
// audience than the keys. Drive every module through its normal path and
// through its refusals, then look for anything secret in what was logged.
func TestMisuse_Leak_logOutputCarriesNoSecretMaterial(t *testing.T) {
	e := hostiletest.NewEnv(t)
	var secrets []string

	j, err := jwt.New[struct{}](e.AC)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := j.CreateTokens(subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = j.VerifyAccessToken(pair.RefreshToken)
	_, _ = j.RotateTokens(pair.AccessToken, struct{}{})
	secrets = append(secrets, pair.AccessToken, pair.RefreshToken)

	pw, err := password.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := pw.Hash(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Verify(plaintext+"x", hash)
	_ = pw.ValidatePolicy("short")
	secrets = append(secrets, plaintext, hash)

	tp, err := totp.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := tp.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tp.VerifyStep(enr.Secret, "000000", 0)
	secrets = append(secrets, enr.Secret, enr.RecoveryCodes[0])

	ak, err := apikey.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	gk, err := ak.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_ = ak.Verify(gk.Key, "00")
	secrets = append(secrets, gk.Key)

	cr, err := credential.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := cr.Issue("reset", subject)
	if err != nil {
		t.Fatal(err)
	}
	_ = cr.Verify("verify", subject, iss.Token, iss.Hash, time.Now())
	secrets = append(secrets, iss.Token)

	fd, err := field.New(e.AC, field.Config{Context: "users.email"})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := fd.Encrypt(fieldText)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fd.Decrypt(ct + "AA")
	secrets = append(secrets, fieldText)

	em, err := email.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = em.ValidateAndNormalize("not-an-address")
	un, err := username.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = un.ValidateAndNormalize("a")

	logged := e.Log.Text()
	if logged == "" {
		t.Fatal("the logger recorded nothing, so this test would pass on any output")
	}
	hostiletest.NoLeak(t, "log output", logged, e.Mat.Priv, e.Mat.Priv.Seed(), e.Mat.Secret)
	for _, s := range secrets {
		if strings.Contains(logged, s) {
			t.Errorf("log output carries a value the caller must show once or never (%d bytes)", len(s))
		}
	}
}

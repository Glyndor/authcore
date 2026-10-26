package leak

import (
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// Modules keep a copy of the key material they need. Printing a module, or a
// copy of it taken by value, must not show that copy.
func TestHostile_Leak_moduleValuesStayQuiet(t *testing.T) {
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
	var nilJWT *jwt.JWT[struct{}]
	var nilTOTP *totp.TOTP
	var nilAPIKey *apikey.APIKey
	var nilCredential *credential.Credential
	checkAll(t, []target{
		{"jwt.JWT pointer", j}, {"jwt.JWT value", *j}, {"jwt.JWT nil", nilJWT},
		{"totp.TOTP pointer", tp}, {"totp.TOTP value", *tp}, {"totp.TOTP nil", nilTOTP},
		{"apikey.APIKey pointer", ak}, {"apikey.APIKey value", *ak}, {"apikey.APIKey nil", nilAPIKey},
		{"credential.Credential pointer", cr}, {"credential.Credential value", *cr},
		{"credential.Credential nil", nilCredential},
	}, e.Mat.Priv, e.Mat.Priv.Seed(), e.Mat.Secret)
}

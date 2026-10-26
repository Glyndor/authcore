package zerovalue

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

const strong = "Correct-Horse-9-Battery-Staple"

func passwordOps(m *password.Password) []op {
	return []op{
		{"Hash", password.ErrInvalidConfig, func() error { _, err := m.Hash(strong); return err }},
		{"Verify", password.ErrInvalidConfig, func() error { _, err := m.Verify(strong, "x"); return err }},
		{"ValidatePolicy", password.ErrInvalidConfig, func() error { return m.ValidatePolicy(strong) }},
	}
}

func emailDomainOps(m *email.Email) []op {
	return []op{
		{"VerifyDomain", email.ErrInvalidConfig, func() error { return m.VerifyDomain(context.Background(), "a@example.com") }},
	}
}

func oauthOps(m *oauth.Client) []op {
	ctx := context.Background()
	return []op{
		{"AuthCodeURL", oauth.ErrInvalidConfig, func() error { _, err := m.AuthCodeURL(); return err }},
		{"Exchange", oauth.ErrInvalidConfig, func() error { _, err := m.Exchange(ctx, "c", "v"); return err }},
		{"UserInfo", oauth.ErrInvalidConfig, func() error { _, err := m.UserInfo(ctx, "t"); return err }},
		{"VerifyIDToken", oauth.ErrIDTokenInvalid, func() error { _, err := m.VerifyIDToken(ctx, "t", "n"); return err }},
	}
}

func usernameOps(m *username.Username) []op {
	return []op{
		{"ValidateAndNormalize", username.ErrInvalidUsername, func() error { _, err := m.ValidateAndNormalize("bob"); return err }},
	}
}

// A nil pointer to any module answers with the module's own error instead of
// a nil dereference.
func TestMisuse_ZeroValue_everyNilModuleRefusesWork(t *testing.T) {
	var ak *apikey.APIKey
	var cr *credential.Credential
	var fd *field.Field
	var pw *password.Password
	var em *email.Email
	var un *username.Username
	var oc *oauth.Client
	run(t, "apikey", apikeyOps(ak))
	run(t, "credential", credentialOps(cr))
	run(t, "field", fieldOps(fd))
	run(t, "password", passwordOps(pw))
	run(t, "email", emailDomainOps(em))
	run(t, "username", usernameOps(un))
	run(t, "oauth", oauthOps(oc))
	hostiletest.NoPanic(t, "email.ValidateAndNormalize", func() {
		if _, err := em.ValidateAndNormalize("a@example.com"); !errors.Is(err, email.ErrInvalidConfig) {
			t.Errorf("nil Email.ValidateAndNormalize: got %v", err)
		}
	})
	hostiletest.NoPanic(t, "apikey.Verify", func() {
		if ak.Verify("k", "h") {
			t.Error("nil APIKey verified a key")
		}
	})
	hostiletest.NoPanic(t, "credential.Verify", func() {
		if err := cr.Verify("p", "s", "t", "h", time.Now()); !errors.Is(err, credential.ErrNotInitialised) {
			t.Errorf("nil Credential.Verify: got %v", err)
		}
	})
}

// A value declared and never built refuses the same calls.
func TestMisuse_ZeroValue_unbuiltPasswordEmailAndOAuthRefuseWork(t *testing.T) {
	var pw password.Password
	var em email.Email
	var oc oauth.Client
	run(t, "password", passwordOps(&pw))
	run(t, "email", emailDomainOps(&em))
	run(t, "oauth", oauthOps(&oc))
	hostiletest.NoPanic(t, "zero oauth.AuthCodeURL", func() {
		if req, err := oc.AuthCodeURL(); err == nil {
			t.Errorf("zero oauth.Client built a URL with an empty client_id: %v", req.URL)
		}
	})
}

// Package lifecycle calls the library in the wrong order or the wrong number of
// times: verify before issue, enroll twice, use after close, build twice on the
// same directory at once. The distracted developer is not malicious, but the
// mistake must not turn into an acceptance, a reused one-time value or a
// corrupted key directory.
package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// Verifying before anything was issued, with empty or junk input, is a refusal.
func TestMisuse_Lifecycle_verifyBeforeIssueRefuses(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, _ := jwt.New[struct{}](e.AC)
	for _, tok := range []string{"", ".", "..", "a.b.c", "Bearer x"} {
		hostiletest.NoPanic(t, "jwt.VerifyAccessToken", func() {
			if _, err := j.VerifyAccessToken(tok); !errors.Is(err, jwt.ErrTokenInvalid) && !errors.Is(err, jwt.ErrTokenMalformed) {
				t.Errorf("jwt on %q = %v; want ErrTokenInvalid or ErrTokenMalformed", tok, err)
			}
			if _, err := j.RotateTokens(tok, struct{}{}); !errors.Is(err, jwt.ErrTokenInvalid) && !errors.Is(err, jwt.ErrTokenMalformed) {
				t.Errorf("jwt rotating %q = %v; want ErrTokenInvalid or ErrTokenMalformed", tok, err)
			}
		})
	}

	cr, _ := credential.New(e.AC)
	for _, c := range [][3]string{{"", "", ""}, {"reset", hostiletest.Subject, ""}, {"reset", hostiletest.Subject, "tok"}} {
		if err := cr.Verify(c[0], c[1], c[2], "", time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("credential %q with an empty stored hash: %v; want ErrInvalidCredential", c, err)
		}
	}

	ak, _ := apikey.New(e.AC)
	if ak.Verify("", "") || ak.Verify("ak_x_y", "") {
		t.Error("apikey accepted a key against an empty stored hash")
	}

	pw, _ := password.New(e.AC)
	for _, h := range []string{"", "x", "$argon2id$", "$argon2id$v=19$m=65536,t=3,p=2$$"} {
		if ok, err := pw.Verify("Correct-Horse-9-Battery-Staple", h); ok || !errors.Is(err, password.ErrInvalidHash) {
			t.Errorf("password.Verify against %q: ok=%v err=%v", h, ok, err)
		}
	}

	fd, _ := field.New(e.AC, field.Config{Context: "users.email"})
	for _, ct := range []string{"", "AA", "not base64 !!", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		hostiletest.NoPanic(t, "field.Decrypt", func() {
			if _, err := fd.Decrypt(ct); !errors.Is(err, field.ErrDecrypt) {
				t.Errorf("field.Decrypt(%q): %v", ct, err)
			}
		})
	}
}

// A TOTP module without a recorder cannot refuse a replay, so Verify demands
// one. The recorder it is given is consulted, and the same code twice fails.
func TestMisuse_Lifecycle_totpReplayIsRefusedThroughTheRecorder(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, _ := totp.New(e.AC)
	enr, err := m.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code := hostiletest.TOTPCode(t, enr.Secret, time.Now())
	ctx := context.Background()

	if err := m.Verify(ctx, enr.Secret, code, nil); !errors.Is(err, totp.ErrStepRecorderRequired) {
		t.Fatalf("Verify without a recorder: %v", err)
	}
	var typedNil *hostiletest.Recorder
	hostiletest.NoPanic(t, "Verify with a typed nil recorder", func() {
		if err := m.Verify(ctx, enr.Secret, code, typedNil); !errors.Is(err, totp.ErrStepRecorderRequired) {
			t.Errorf("a typed nil recorder: %v; want ErrStepRecorderRequired", err)
		}
	})

	rec := &hostiletest.Recorder{}
	if err := m.Verify(ctx, enr.Secret, code, rec); err != nil {
		t.Fatalf("first use of the code: %v", err)
	}
	if err := m.Verify(ctx, enr.Secret, code, rec); !errors.Is(err, totp.ErrCodeReused) {
		t.Fatalf("second use of the same code: %v", err)
	}
	if rec.Calls == 0 {
		t.Fatal("the recorder was never consulted")
	}

	step, err := m.VerifyStep(enr.Secret, code, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyStep(enr.Secret, code, step); !errors.Is(err, totp.ErrCodeReused) {
		t.Fatalf("VerifyStep with the step it returned: %v", err)
	}
}

// Enrolling twice gives two independent enrolments. A code or recovery code of
// the first must not work for the second.
func TestMisuse_Lifecycle_enrollTwiceGivesIndependentSecrets(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, _ := totp.New(e.AC)
	a, err := m.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a.Secret == b.Secret {
		t.Fatal("two enrolments share a secret")
	}
	if _, err := m.VerifyStep(b.Secret, hostiletest.TOTPCode(t, a.Secret, time.Now()), 0); !errors.Is(err, totp.ErrInvalidCode) {
		t.Errorf("a code of the first enrolment against the second secret: %v; want ErrInvalidCode", err)
	}
	if _, ok := m.VerifyRecoveryCode(a.RecoveryCodes[0], b.RecoveryHashes); ok {
		t.Error("a recovery code of the first enrolment matches the second enrolment's hashes")
	}
	if i, ok := m.VerifyRecoveryCode(a.RecoveryCodes[3], a.RecoveryHashes); !ok || i != 3 {
		t.Errorf("control: own recovery code not found at its index (%d, %v)", i, ok)
	}
}

// A refresh token is not an access token, and the other way round, in every
// direction a call could mix them up.
func TestMisuse_Lifecycle_tokenKindsDoNotCrossOver(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, _ := jwt.New[struct{}](e.AC)
	pair, err := j.CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.VerifyAccessToken(pair.RefreshToken); !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Errorf("refresh token as access token: %v", err)
	}
	if _, err := j.RotateTokens(pair.AccessToken, struct{}{}); !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Errorf("access token as refresh token: %v", err)
	}
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Errorf("control: the refresh token does not rotate: %v", err)
	}
}

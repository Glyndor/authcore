package jwttest_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

func TestKeys_formAWorkingPair(t *testing.T) {
	k := jwttest.NewKeys(t)

	msg := []byte("message")
	if !ed25519.Verify(k.PublicKey(), msg, ed25519.Sign(k.PrivateKey(), msg)) {
		t.Fatal("the public key does not verify what the private key signed")
	}
	if len(k.RefreshSecret()) != 32 || k.KeyID() == "" {
		t.Errorf("secret %d bytes, kid %q; want 32 bytes and a kid", len(k.RefreshSecret()), k.KeyID())
	}
}

func TestProvider_servesItsKeysAndASilentLogger(t *testing.T) {
	p := jwttest.NewProvider(t)

	if p.Keys().KeyID() != p.K.KeyID() {
		t.Error("Keys() must return the provider's own key material")
	}
	if p.Config().Timezone != authcore.DefaultConfig().Timezone {
		t.Error("Config() must return the default authcore configuration")
	}
	l := p.Logger()
	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x")
}

func TestHeader_decodesTheJOSEHeader(t *testing.T) {
	k := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](k, jwttest.DefaultConfig())
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	h := jwttest.Header(t, pair.AccessToken)
	if h["alg"] != "EdDSA" || h["kid"] != k.KeyID() {
		t.Errorf("header = %v, want EdDSA and the key's kid", h)
	}
}

// fatalRecorder stands in for *testing.T so Header's failure paths can run:
// Fatalf records the message and stops the call the way the real one does.
type fatalRecorder struct {
	testing.TB
	msg string
}

type stopped struct{}

func (r *fatalRecorder) Helper() {}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.msg = fmt.Sprintf(format, args...)
	panic(stopped{})
}

// recoverStopped swallows the panic fatalRecorder.Fatalf raises and lets any
// other panic through.
func recoverStopped() {
	if v := recover(); v != nil {
		if _, ok := v.(stopped); !ok {
			panic(v)
		}
	}
}

func TestHeader_failsOnATokenItCannotDecode(t *testing.T) {
	for name, tok := range map[string]string{
		"two parts":       "only.two",
		"not base64":      "!!!.payload.sig",
		"header not JSON": "bm90LWpzb24.payload.sig",
	} {
		t.Run(name, func(t *testing.T) {
			r := &fatalRecorder{TB: t}
			func() {
				defer recoverStopped()
				jwttest.Header(r, tok)
			}()
			if r.msg == "" {
				t.Fatalf("Header(%q) did not fail", tok)
			}
		})
	}
}

func TestRig_issuesVerifiesAndRotatesUnderItsOwnClock(t *testing.T) {
	j := jwttest.NewRig[struct{}](jwttest.NewKeys(t), jwttest.DefaultConfig())

	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if h := j.HashRefreshToken(pair.RefreshToken); h != pair.RefreshTokenHash || !j.VerifyRefreshTokenHash(pair.RefreshToken, h) {
		t.Error("the rig's hash must be the one the pair carries")
	}

	j.Now = jwttest.Epoch.Add(time.Second)
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Fatalf("RotateTokens: %v", err)
	}
	j.Now = jwttest.Epoch.Add(48 * time.Hour)
	if _, err := j.VerifyAccessToken(pair.AccessToken); !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Fatalf("a token past its expiry = %v, want ErrTokenExpired", err)
	}
}

func TestRig_acceptsPreviousKeysAlongsideTheCurrentOne(t *testing.T) {
	old := jwttest.NewKeys(t)
	pair, err := jwttest.NewRig[struct{}](old, jwttest.DefaultConfig()).CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	cfg := jwttest.DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{old.Pub}
	next := jwttest.NewRig[struct{}](jwttest.NewKeys(t), cfg)
	if len(next.Keys) != 2 {
		t.Fatalf("%d accepted keys, want the current one and one previous", len(next.Keys))
	}
	if _, err := next.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("a token under the previous key = %v, want accepted", err)
	}

	stranger := jwttest.NewRig[struct{}](jwttest.NewKeys(t), jwttest.DefaultConfig())
	if _, err := stranger.VerifyAccessToken(pair.AccessToken); !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Fatalf("a token under an unlisted key = %v, want ErrTokenInvalid", err)
	}
}

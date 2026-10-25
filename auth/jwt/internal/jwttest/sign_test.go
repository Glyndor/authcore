package jwttest_test

import (
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

func TestSign_producesTokensTheRigAccepts(t *testing.T) {
	k := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](k, jwttest.DefaultConfig())
	jti := "019600ab-0000-7000-8000-000000000001"

	access := jwttest.SignAccess(t, claims.NewAccess(j.Cfg.Issuer, jwttest.Subject, jti, j.Cfg.Audience, struct{}{}, jwttest.Epoch, time.Minute), k.Priv, k.KeyID())
	if c, err := j.VerifyAccessToken(access); err != nil || c.ID != jti {
		t.Errorf("hand-signed access token = %+v, %v; want it accepted", c, err)
	}
	refresh := jwttest.SignRefresh(t, claims.NewRefresh(j.Cfg.Issuer, jwttest.Subject, jti, "rid", j.Cfg.Audience, jwttest.Epoch, time.Minute), k.Priv, k.KeyID())
	if _, err := j.RotateTokens(refresh, struct{}{}); err != nil {
		t.Errorf("hand-signed refresh token did not rotate: %v", err)
	}
}

func TestSign_failsTheTestWhenTheClaimsCannotBeEncoded(t *testing.T) {
	k := jwttest.NewKeys(t)
	r := &fatalRecorder{TB: t}
	func() {
		defer recoverStopped()
		jwttest.SignAccess(r, claims.NewAccess("iss", jwttest.Subject, "jti", []string{"aud"}, make(chan int), jwttest.Epoch, time.Minute), k.Priv, k.KeyID())
	}()
	if r.msg == "" {
		t.Fatal("signing claims that cannot be encoded did not fail the test")
	}
}

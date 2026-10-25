package verify_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"

	gjwt "github.com/golang-jwt/jwt/v5"
)

func TestVerifyAccessToken_wrongIssuerRejectsToken(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.Issuer = "https://auth.service-a.example.com"
	prov := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](prov, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// A second service that happens to share the signing key (e.g. accidental
	// key reuse across microservices) must not accept a token issued by the
	// first service. The iss claim must be checked on verification. Both
	// modules must be built from the same provider so they share the key id
	// and the verification map; otherwise an unknown-key rejection fires
	// before the issuer check ever runs.
	cfg2 := jwttest.DefaultConfig()
	cfg2.Issuer = "https://auth.service-b.example.com"
	j2 := jwttest.NewRig[struct{}](prov, cfg2)

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid when issuer does not match, got %v", err)
	}
}

func TestVerifyAccessToken_missingKidRejectsToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())

	// An attacker may try to strip the kid header entirely, betting that
	// the verifier trusts the (single) configured public key regardless.
	// The verifier must reject tokens whose kid does not match, which
	// includes tokens where kid is absent.
	cl := claims.NewAccess(j.Cfg.Issuer, jwttest.Subject, "019600ab-0000-7000-8000-000000000002", j.Cfg.Audience, struct{}{}, jwttest.Epoch, j.Cfg.AccessTokenTTL)
	cl.Type = claims.TypeAccess
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, cl)
	// Deliberately do not set token.Header["kid"].
	stripped, err := token.SignedString(j.K.Priv)
	if err != nil {
		t.Fatalf("sign kid-less token: %v", err)
	}

	_, err = j.VerifyAccessToken(stripped)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for missing kid, got %v", err)
	}
}

func TestRotateTokens_unknownKidRejectsRefreshToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())

	// Mirror of the access-token kid check but on the rotation path. A
	// refresh token with a kid the module does not recognise must be
	// rejected before it is exchanged for a fresh pair.
	cl := claims.NewRefresh(j.Cfg.Issuer, jwttest.Subject, "019600ab-0000-7000-8000-000000000003", "", j.Cfg.Audience, jwttest.Epoch, j.Cfg.RefreshTokenTTL)
	cl.Type = claims.TypeRefresh
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, cl)
	token.Header["kid"] = "attacker-controlled-kid"
	tampered, err := token.SignedString(j.K.Priv)
	if err != nil {
		t.Fatalf("sign tampered refresh token: %v", err)
	}

	_, err = j.RotateTokens(tampered, struct{}{})
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for unknown kid on refresh, got %v", err)
	}
}

func TestVerifyAccessToken_unknownKidRejectsToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())

	// Craft a token signed with the module's private key (so the signature
	// is valid) but with a "kid" header the verifier does not recognise.
	// This simulates an attacker who has obtained a signing key but whose
	// "kid" is not on the verifier's trusted list — the kid check must
	// reject the token before it is accepted.
	cl := claims.NewAccess(j.Cfg.Issuer, jwttest.Subject, "019600ab-0000-7000-8000-000000000001", j.Cfg.Audience, struct{}{}, jwttest.Epoch, j.Cfg.AccessTokenTTL)
	cl.Type = claims.TypeAccess
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, cl)
	token.Header["kid"] = "attacker-controlled-kid"
	tampered, err := token.SignedString(j.K.Priv)
	if err != nil {
		t.Fatalf("sign tampered token: %v", err)
	}

	_, err = j.VerifyAccessToken(tampered)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for unknown kid, got %v", err)
	}
}

func TestRotateTokens_wrongIssuerRejectsRefreshToken(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.Issuer = "https://auth.service-a.example.com"
	prov := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](prov, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	cfg2 := jwttest.DefaultConfig()
	cfg2.Issuer = "https://auth.service-b.example.com"
	j2 := jwttest.NewRig[struct{}](prov, cfg2)

	_, err := j2.RotateTokens(pair.RefreshToken, struct{}{})
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid when issuer does not match, got %v", err)
	}
}

func TestRotateTokens_audienceEmbeddedInRefreshToken(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newRig[struct{}](t, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Rotation must succeed — refresh token carries the same audience.
	j.Now = jwttest.Epoch.Add(time.Second)
	_, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}
}

// ---- VerifyAccessToken() ----------------------------------------------------

func TestVerifyAccessToken_validTokenReturnsCorrectClaims(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099", struct{}{})

	cl, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if cl.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099" {
		t.Errorf("Subject = %q, want %q", cl.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099")
	}
	if !cl.IssuedAt.Equal(jwttest.Epoch) {
		t.Errorf("IssuedAt = %v, want %v", cl.IssuedAt, jwttest.Epoch)
	}
}

func TestVerifyAccessToken_expiredTokenReturnsErrTokenExpired(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newRig[struct{}](t, cfg)

	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Advance clock past expiry.
	j.Now = jwttest.Epoch.Add(11 * time.Minute)

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccessToken_tokenAtExactExpiryIsExpired(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newRig[struct{}](t, cfg)

	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	// golang-jwt/v5 uses cmp.Before(exp+leeway), so a token whose exp has
	// already been reached is rejected at the exact expiry second. Verify
	// that boundary.
	j.Now = jwttest.Epoch.Add(10 * time.Minute)

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Errorf("token at the exact expiry second should return ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccessToken_tamperedSignatureReturnsErrTokenInvalid(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Modify a middle character of the signature segment to guarantee the
	// decoded bytes change. The last base64url char of an Ed25519 signature
	// encodes only 2 meaningful bits — altering it does not affect the
	// decoded byte slice, so we target a position well inside the signature.
	token := pair.AccessToken
	mid := len(token) - 10
	orig := token[mid]
	replacement := byte('A')
	if orig == 'A' {
		replacement = 'B'
	}
	tampered := token[:mid] + string(replacement) + token[mid+1:]

	_, err := j.VerifyAccessToken(tampered)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for a tampered signature, got %v", err)
	}
}

func TestVerifyAccessToken_malformedTokenReturnsErrTokenMalformed(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())

	cases := []string{"", "only-one-part", "two.parts", "a.b.c.d"}
	for _, tc := range cases {
		_, err := j.VerifyAccessToken(tc)
		if !errors.Is(err, jwterr.ErrTokenMalformed) {
			t.Errorf("input %q: expected ErrTokenMalformed, got %v", tc, err)
		}
	}
}

func TestVerifyAccessToken_rejectsRefreshToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	_, err := j.VerifyAccessToken(pair.RefreshToken)
	if !errors.Is(err, jwterr.ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestVerifyAccessToken_rejectsTokenFromDifferentKey(t *testing.T) {
	p1 := jwttest.NewKeys(t)
	p2 := jwttest.NewKeys(t) // different Ed25519 key pair

	j1 := jwttest.NewRig[struct{}](p1, jwttest.DefaultConfig())
	j2 := jwttest.NewRig[struct{}](p2, jwttest.DefaultConfig())

	pair, _ := j1.CreateTokens(jwttest.Subject, struct{}{})

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("token signed by j1 should be invalid for j2, got %v", err)
	}
}

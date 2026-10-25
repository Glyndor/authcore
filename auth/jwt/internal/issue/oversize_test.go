package issue_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/issue"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// TestCreate_rejectsOversizedPayload pins the symmetry between issuance
// and verification: a payload large enough to push the signed token past the
// 8 KiB cap must be rejected at issue time with a message that names the
// limit and the actual size, so the operator does not discover it on the
// next request when the verifier calls the token malformed.
func TestCreateTokens_rejectsOversizedPayload(t *testing.T) {
	j := newRig[string](t, jwttest.DefaultConfig())

	huge := strings.Repeat("a", 8192)
	pair, err := j.CreateTokens(jwttest.Subject, huge)
	if err == nil {
		t.Fatalf("CreateTokens with an oversized payload must fail, got pair %+v", pair)
	}
	if pair != nil {
		t.Errorf("CreateTokens returned a non-nil pair alongside the error: %+v", pair)
	}
	if !errors.Is(err, jwterr.ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "8192") {
		t.Errorf("error message must name the 8192 byte limit, got %q", msg)
	}
	if !strings.Contains(msg, "exceeds") {
		t.Errorf("error message must name the failure shape, got %q", msg)
	}
}

// TestCreate_oversizedPayloadJustUnderBoundAccepts is the acceptance
// twin: a payload just under the cap must issue and verify without error.
// The exact boundary depends on header, signature and the other claims, so
// the test picks a small string that is well inside the cap rather than
// probing for the threshold.
func TestCreateTokens_oversizedPayloadJustUnderBoundAccepts(t *testing.T) {
	j := newRig[string](t, jwttest.DefaultConfig())

	pair, err := j.CreateTokens(jwttest.Subject, strings.Repeat("a", 1024))
	if err != nil {
		t.Fatalf("CreateTokens under the cap must succeed, got %v", err)
	}
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("a token issued just under the cap must verify, got %v", err)
	}
}

// TestCreate_rejectsOversizedIssuer is the mirror case for the issuer
// string. A long issuer blows the refresh token past the cap, since the
// refresh token does not carry extra claims.
func TestCreateTokens_rejectsOversizedIssuer(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.Issuer = strings.Repeat("i", 8192)
	j := newRig[struct{}](t, cfg)
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err == nil {
		t.Fatalf("CreateTokens with an oversized issuer must fail, got pair %+v", pair)
	}
	if !errors.Is(err, jwterr.ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized, got %v", err)
	}
}

// Issuance refuses a pair whose refresh token would exceed the size the
// verifier accepts. The access token is smaller (no extra claims here, but a
// shorter claim set), so an issuer length exists where only the refresh
// token overflows; #443 added the check and nothing exercised it.
func TestCreateTokens_refusesAnOversizedRefreshToken(t *testing.T) {
	long := jwttest.DefaultConfig()
	long.Issuer = strings.Repeat("i", 5806)
	j := newRig[struct{}](t, long)
	if _, err := j.CreateTokens(jwttest.Subject, struct{}{}); !errors.Is(err, jwterr.ErrTokenOversized) {
		t.Fatalf("CreateTokens with a 5806-byte issuer = %v, want ErrTokenOversized", err)
	}

	fits := jwttest.DefaultConfig()
	fits.Issuer = strings.Repeat("i", 5600)
	j = newRig[struct{}](t, fits)
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens with a 5600-byte issuer: %v, want a pair", err)
	}
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Fatalf("the refresh token of that pair does not rotate: %v", err)
	}
}

// An extra claim the JSON encoder cannot serialise makes the signature fail,
// and the failure names the token that was being signed.
func TestTokens_reportsASigningFailure(t *testing.T) {
	j := newRig[chan int](t, jwttest.DefaultConfig())

	_, err := issue.Tokens(j.IssueParams(), jwttest.Epoch, jwttest.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0002", make(chan int))
	if err == nil || !strings.Contains(err.Error(), "sign access token") {
		t.Fatalf("Tokens with an unserialisable extra = %v, want a sign access token failure", err)
	}
}

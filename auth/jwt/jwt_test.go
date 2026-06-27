package jwt

// Internal test package (package jwt, not package jwt_test) so that tests
// can inject a clock.Fixed into the unexported jwt.clock field without
// exposing time control as part of the public API.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/clock"
)

// ---- test infrastructure ----------------------------------------------------

// fakeKeys satisfies authcore.Keys using in-memory key material.
type fakeKeys struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

func (k *fakeKeys) PrivateKey() ed25519.PrivateKey { return k.priv }
func (k *fakeKeys) PublicKey() ed25519.PublicKey   { return k.pub }
func (k *fakeKeys) RefreshSecret() []byte          { return k.secret }
func (k *fakeKeys) KeyID() string                  { return "test0000test0000" }

// fakeProvider satisfies authcore.Provider using in-memory state.
type fakeProvider struct{ keys *fakeKeys }

func (p *fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (p *fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (p *fakeProvider) Keys() authcore.Keys     { return p.keys }

// silentLogger satisfies authcore.Logger and discards all output.
type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

// newFakeProvider creates a fakeProvider with freshly generated key material.
func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	// Go 1.26: rand parameter to GenerateKey is always ignored — nil is explicit.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate test Ed25519 keys: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate test HMAC secret: %v", err)
	}
	return &fakeProvider{keys: &fakeKeys{priv: priv, pub: pub, secret: secret}}
}

// epoch is the fixed reference time used in all time-sensitive tests.
var epoch = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

// newTestJWT constructs a JWT[T] with the given config and a fixed clock pinned
// to epoch. The clock can be overridden per-test by assigning j.clock.
func newTestJWT[T any](t *testing.T, p authcore.Provider, cfg Config) *JWT[T] {
	t.Helper()
	j, err := New[T](p, cfg)
	if err != nil {
		t.Fatalf("jwt.New() unexpected error: %v", err)
	}
	j.clock = clock.Fixed(epoch)
	return j
}

// tokenHeader decodes the JOSE header of a compact JWT string.
func tokenHeader(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(data, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}

// testSubject is a valid UUID v7 used across most tests.
const testSubject = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"

// ---- New() ------------------------------------------------------------------

func TestNew_defaultConfigSucceeds(t *testing.T) {
	_, err := New[struct{}](newFakeProvider(t), DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_negativeTTLReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = -1 * time.Second

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_accessTTLExactlyAtCeilingAccepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 24 * time.Hour        // exactly at the cap
	cfg.RefreshTokenTTL = 365*24*time.Hour - 1 // any value above access works; keep below its own cap

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Errorf("TTL exactly at ceiling must be accepted, got %v", err)
	}
}

func TestNew_refreshTTLExactlyAtCeilingAccepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 15 * time.Minute
	cfg.RefreshTokenTTL = 365 * 24 * time.Hour // exactly at the cap

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Errorf("refresh TTL exactly at ceiling must be accepted, got %v", err)
	}
}

func TestNew_accessTTLAboveCeilingReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 48 * time.Hour // above 24 h ceiling
	cfg.RefreshTokenTTL = 96 * time.Hour

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_refreshTTLAboveCeilingReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RefreshTokenTTL = 2 * 365 * 24 * time.Hour // above 365-day ceiling

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_refreshTTLShorterThanAccessReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 30 * time.Minute
	cfg.RefreshTokenTTL = 15 * time.Minute // shorter than access

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_implementsModule(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	var _ authcore.Module = j // compile-time checked by var _ above, belt+braces here
	if j.Name() != "jwt" {
		t.Errorf("Name() = %q, want %q", j.Name(), "jwt")
	}
}

// ---- CreateTokens() ---------------------------------------------------------

func TestCreateTokens_returnsNonEmptyPair(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if pair.AccessTokenExpiresAt.IsZero() {
		t.Error("AccessTokenExpiresAt is zero")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}
	if pair.RefreshTokenExpiresAt.IsZero() {
		t.Error("RefreshTokenExpiresAt is zero")
	}
	if pair.RefreshTokenHash == "" {
		t.Error("RefreshTokenHash is empty")
	}
}

func TestCreateTokens_invalidSubjectReturnsError(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	cases := []string{
		"",
		"not-a-uuid",
		"123",
		"0191b432-b5a7-7c4f-b2e6",               // too short
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e00001", // too long
		"550e8400-e29b-11d4-a716-446655440000",  // v1 — rejected
		"550e8400-e29b-31d4-a716-446655440000",  // v3 — rejected
		"550e8400-e29b-41d4-a716-446655440000",  // v4 — rejected
		"550e8400-e29b-61d4-a716-446655440000",  // v6 — rejected
	}
	for _, tc := range cases {
		_, err := j.CreateTokens(tc, struct{}{})
		if !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("subject %q: expected ErrInvalidSubject, got %v", tc, err)
		}
	}
}

func TestCreateTokens_uppercaseUUIDIsNormalised(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	upper := "0191B432-B5A7-7C4F-B2E6-7A3F1D2E0000"
	pair, err := j.CreateTokens(upper, struct{}{})
	if err != nil {
		t.Fatalf("uppercase UUID v7 should be accepted, got %v", err)
	}

	claims, _ := j.VerifyAccessToken(pair.AccessToken)
	if claims.Subject != strings.ToLower(upper) {
		t.Errorf("Subject = %q, want lowercase %q", claims.Subject, strings.ToLower(upper))
	}
}

func TestCreateTokens_validUUIDVersionsAreAccepted(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	cases := []string{
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e4c5a", // v7 lowercase
		"0191B432-B5A7-7C4F-B2E6-7A3F1D2E4C5A", // v7 uppercase
	}
	for _, tc := range cases {
		if _, err := j.CreateTokens(tc, struct{}{}); err != nil {
			t.Errorf("subject %q: unexpected error %v", tc, err)
		}
	}
}

func TestCreateTokens_subjectPreservedInAccessToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042", struct{}{})

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042")
	}
}

func TestCreateTokens_issuerPreservedInClaims(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "my-service"
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	claims, _ := j.VerifyAccessToken(pair.AccessToken)
	if claims.Issuer != "my-service" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "my-service")
	}
}

func TestCreateTokens_accessAndRefreshTokensAreDifferent(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})
	if pair.AccessToken == pair.RefreshToken {
		t.Error("AccessToken and RefreshToken must not be equal")
	}
}

func TestCreateTokens_consecutiveCallsProduceUniqueRefreshTokens(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens(testSubject, struct{}{})
	p2, _ := j.CreateTokens(testSubject, struct{}{})
	if p1.RefreshToken == p2.RefreshToken {
		t.Error("consecutive CreateTokens calls must not produce equal refresh tokens")
	}
	if p1.RefreshTokenHash == p2.RefreshTokenHash {
		t.Error("consecutive CreateTokens calls must not produce equal refresh hashes")
	}
}

func TestCreateTokens_accessTokenExpiryIsCorrect(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 5 * time.Minute
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})
	claims, _ := j.VerifyAccessToken(pair.AccessToken)

	want := epoch.Add(5 * time.Minute)
	if !claims.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, want)
	}
}

func TestCreateTokens_expiryFieldsMatchConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 5 * time.Minute
	cfg.RefreshTokenTTL = 12 * time.Hour
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	wantAccess := epoch.Add(5 * time.Minute)
	if !pair.AccessTokenExpiresAt.Equal(wantAccess) {
		t.Errorf("AccessTokenExpiresAt = %v, want %v", pair.AccessTokenExpiresAt, wantAccess)
	}

	wantRefresh := epoch.Add(12 * time.Hour)
	if !pair.RefreshTokenExpiresAt.Equal(wantRefresh) {
		t.Errorf("RefreshTokenExpiresAt = %v, want %v", pair.RefreshTokenExpiresAt, wantRefresh)
	}
}

func TestCreateTokens_refreshHashMatchesHashRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	got := j.HashRefreshToken(pair.RefreshToken)
	if got != pair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(RefreshToken) = %q, want %q", got, pair.RefreshTokenHash)
	}
}

func TestCreateTokens_sessionIDIsUUIDv7(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if pair.SessionID == "" {
		t.Fatal("SessionID is empty")
	}
	id := pair.SessionID
	if len(id) != 36 {
		t.Fatalf("SessionID length = %d, want 36", len(id))
	}
	if id[14] != '7' {
		t.Errorf("SessionID version digit = %q, want '7'", id[14])
	}
	if id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b' {
		t.Errorf("SessionID variant nibble = %q, want 8/9/a/b", id[19])
	}
}

func TestCreateTokens_consecutiveSessionIDsAreUnique(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens(testSubject, struct{}{})
	p2, _ := j.CreateTokens(testSubject, struct{}{})
	if p1.SessionID == p2.SessionID {
		t.Error("consecutive CreateTokens calls must not produce equal SessionIDs")
	}
}

// ---- audience ---------------------------------------------------------------

func TestCreateTokens_audienceEmbeddedInAccessToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://api.example.com" {
		t.Errorf("Audience = %v, want [https://api.example.com]", claims.Audience)
	}
}

func TestCreateTokens_wrongAudienceRejectsToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Verify with a different audience config — must fail.
	cfg2 := DefaultConfig()
	cfg2.Audience = []string{"https://other.example.com"}
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), cfg2)
	j2.priv = j.priv
	j2.pub = j.pub

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if err == nil {
		t.Error("expected error when audience does not match, got nil")
	}
}

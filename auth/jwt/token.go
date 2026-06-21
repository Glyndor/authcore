package jwt

// token.go contains the internal JWT implementation backed by github.com/golang-jwt/jwt/v5.
//
// Token format (RFC 7519 / RFC 8037 EdDSA):
//
//	BASE64URL(header) + "." + BASE64URL(payload) + "." + BASE64URL(signature)
//
// Header  : {"alg":"EdDSA","kid":"<key-id>","typ":"JWT"}
// Payload : JSON object with registered + private claims
// Signature: Ed25519 signature over the raw "header.payload" ASCII bytes
//
// Access token payload : iss, sub, iat, exp, jti, type, extra
// Refresh token payload: iss, sub, iat, exp, jti, type  (no extra)

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// tokenTypeAccess and tokenTypeRefresh are the values of the private "type"
// claim used to distinguish the two token kinds at verification time.
const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

// accessClaims is the internal claim set for access tokens.
// T carries the application-specific fields stored under the "extra" key.
type accessClaims[T any] struct {
	gjwt.RegisteredClaims
	Type  string `json:"type"`
	Extra T      `json:"extra,omitempty"`
}

// refreshClaims is the minimal internal claim set for refresh tokens.
// Refresh tokens carry no application-specific data (no extra field).
type refreshClaims struct {
	gjwt.RegisteredClaims
	Type string `json:"type"`
}

// newAccessClaims builds the claim set for an access token.
func newAccessClaims[T any](issuer, subject, jti string, audience []string, extra T, now time.Time, ttl time.Duration) *accessClaims[T] {
	return &accessClaims[T]{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ID:        jti,
			Audience:  gjwt.ClaimStrings(audience),
			IssuedAt:  gjwt.NewNumericDate(now),
			ExpiresAt: gjwt.NewNumericDate(now.Add(ttl)),
		},
		Type:  tokenTypeAccess,
		Extra: extra,
	}
}

// newRefreshClaims builds the claim set for a refresh token.
func newRefreshClaims(issuer, subject, jti string, audience []string, now time.Time, ttl time.Duration) *refreshClaims {
	return &refreshClaims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ID:        jti,
			Audience:  gjwt.ClaimStrings(audience),
			IssuedAt:  gjwt.NewNumericDate(now),
			ExpiresAt: gjwt.NewNumericDate(now.Add(ttl)),
		},
		Type: tokenTypeRefresh,
	}
}

// signToken encodes claims as a signed EdDSA JWT and returns the compact serialisation.
// kid is embedded in the JOSE header so verifiers can select the correct public key.
func signToken(claims gjwt.Claims, key ed25519.PrivateKey, kid string) (string, error) {
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// verifyAccessToken validates the compact JWT string and returns the decoded access claims.
// now is injected to allow deterministic testing via clock.Fixed.
// issuer and audience are the expected "iss" and "aud" values the token must
// carry. Enforcing both defends against cross-service key reuse, where a token
// signed by the same key but issued for a different service would otherwise be
// accepted here.
// leeway is added to the expiration window to tolerate small clock skew between servers.
func verifyAccessToken[T any](tokenStr string, pub ed25519.PublicKey, kid string, now time.Time, issuer, audience string, leeway time.Duration) (*accessClaims[T], error) {
	var c accessClaims[T]
	_, err := gjwt.ParseWithClaims(
		tokenStr, &c,
		eddsaKeyFunc(pub, kid),                             // enforce EdDSA alg + kid match; rejects HS256/RS256 confusion attacks and unknown key IDs
		gjwt.WithTimeFunc(func() time.Time { return now }), // inject clock so tests can freeze time
		gjwt.WithExpirationRequired(),                      // reject tokens without an exp claim
		gjwt.WithIssuedAt(),                                // reject tokens with iat in the future
		gjwt.WithIssuer(issuer),                            // token must be issued by this service
		gjwt.WithAudience(audience),                        // token must contain this audience value
		gjwt.WithLeeway(leeway),                            // tolerate small clock drift between servers
	)
	if err != nil {
		return nil, mapJWTError(err)
	}
	return &c, nil
}

// verifyRefreshToken validates the compact JWT string and returns the decoded refresh claims.
// issuer and audience are the expected "iss" and "aud" values the token must
// carry. Enforcing both defends against cross-service key reuse, where a token
// signed by the same key but issued for a different service would otherwise be
// accepted here.
// leeway is added to the expiration window to tolerate small clock skew between servers.
func verifyRefreshToken(tokenStr string, pub ed25519.PublicKey, kid string, now time.Time, issuer, audience string, leeway time.Duration) (*refreshClaims, error) {
	var c refreshClaims
	_, err := gjwt.ParseWithClaims(
		tokenStr, &c,
		eddsaKeyFunc(pub, kid),                             // enforce EdDSA alg + kid match; rejects HS256/RS256 confusion attacks and unknown key IDs
		gjwt.WithTimeFunc(func() time.Time { return now }), // inject clock so tests can freeze time
		gjwt.WithExpirationRequired(),                      // reject tokens without an exp claim
		gjwt.WithIssuedAt(),                                // reject tokens with iat in the future
		gjwt.WithIssuer(issuer),                            // token must be issued by this service
		gjwt.WithAudience(audience),                        // token must contain this audience value
		gjwt.WithLeeway(leeway),                            // tolerate small clock drift between servers
	)
	if err != nil {
		return nil, mapJWTError(err)
	}
	return &c, nil
}

// eddsaKeyFunc returns a gjwt.Keyfunc that enforces EdDSA, validates the
// token's "kid" header against the expected value, and returns pub.
// Rejecting unknown kids narrows the verifier to keys the operator has
// actually authorised, which matters once key rotation is in play (the
// verifier would otherwise happily try pub against every incoming kid).
func eddsaKeyFunc(pub ed25519.PublicKey, expectedKID string) gjwt.Keyfunc {
	return func(t *gjwt.Token) (any, error) {
		// Explicitly reject any algorithm that is not EdDSA.
		// Without this check an attacker could craft a token with alg=HS256
		// and sign it using the public key as the HMAC secret — a well-known
		// algorithm confusion attack that allows signature forgery.
		if _, ok := t.Method.(*gjwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("%w: unexpected alg %q", ErrTokenInvalid, t.Header["alg"])
		}
		// Reject tokens that did not declare a kid or declared one we do not
		// recognise. Empty expectedKID disables the check (defence in depth
		// for callers that legitimately sign without a kid header).
		if expectedKID != "" {
			kid, _ := t.Header["kid"].(string)
			if kid != expectedKID {
				return nil, fmt.Errorf("%w: unexpected kid %q", ErrTokenInvalid, kid)
			}
		}
		return pub, nil
	}
}

// mapJWTError converts golang-jwt sentinel errors to our public sentinels.
// This decouples callers from the underlying library's error types, so we can
// swap or upgrade the JWT library without breaking the public API.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, gjwt.ErrTokenExpired):
		// Expired tokens are CLIENT-SAFE to communicate; prompt the client to refresh.
		return ErrTokenExpired
	case errors.Is(err, gjwt.ErrTokenSignatureInvalid):
		// Bad signature — could be a wrong key, a tampered token, or an unsupported algorithm.
		return ErrTokenInvalid
	case errors.Is(err, gjwt.ErrTokenMalformed):
		// Not a valid three-part JWT at all — likely user error or a non-token string.
		return ErrTokenMalformed
	default:
		// Wrap any other library error under ErrTokenInvalid so callers
		// can handle it generically without catching internal library types.
		return fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
}

// accessClaimsToClaims converts internal accessClaims to the public Claims type.
func accessClaimsToClaims[T any](c *accessClaims[T]) *Claims[T] {
	// gjwt.NumericDate pointers can be nil if the claim is absent in the token.
	// Extract them defensively to avoid nil pointer dereferences.
	var iat, exp time.Time
	if c.IssuedAt != nil {
		iat = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		exp = c.ExpiresAt.Time
	}
	return &Claims[T]{
		Subject:   c.Subject,
		Issuer:    c.Issuer,
		Audience:  []string(c.Audience),
		TokenID:   c.ID,
		IssuedAt:  iat.UTC(), // normalise to UTC regardless of the server's local timezone
		ExpiresAt: exp.UTC(),
		Extra:     c.Extra,
	}
}

// computeHMAC returns the HMAC-SHA256 hex digest of token keyed with secret.
func computeHMAC(token string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateJTI returns a UUID v7 string suitable for use as the "jti" claim.
// The 48-bit timestamp comes from now; the remaining bits are cryptographically random.
//
// Format: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx (RFC 9562 §5.7).
func generateJTI(now time.Time) (string, error) {
	ms := now.UnixMilli()

	var b [16]byte
	// Bytes 0-5: 48-bit Unix timestamp in milliseconds.
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	// Bytes 6-15: random.
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("generate token ID: %w", err)
	}

	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx (RFC 4122)

	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), nil
}

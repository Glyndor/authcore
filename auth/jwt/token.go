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
// Refresh token payload: iss, sub, iat, exp, jti, type, rid  (no extra). Each refresh
// token carries a random rid, so two tokens of one session never compare equal,
// whatever the clock says.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// maxTokenLen caps the length of a token string before it is parsed. A genuine
// access/refresh token is a few hundred bytes; refusing anything over 8 KiB
// stops an attacker from forcing base64+JSON work on a multi-megabyte string
// before the signature is even checked.
const maxTokenLen = 8 * 1024

// accessClaims is the internal claim set for access tokens.
// T carries the application-specific fields stored under the "extra" key.
type accessClaims[T any] struct {
	gjwt.RegisteredClaims
	Type  string `json:"type"`
	Extra T      `json:"extra,omitempty"`
}

// refreshClaims is the minimal internal claim set for refresh tokens.
// Refresh tokens carry no application-specific data (no extra field) but do
// carry a random RID ("rid") so two tokens of one session never compare equal,
// even when issued in the same wall-clock second. RID is omitted when empty,
// which keeps refresh tokens issued before this field existed parseable.
type refreshClaims struct {
	gjwt.RegisteredClaims
	Type string `json:"type"`
	RID  string `json:"rid,omitempty"`
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
// rid is the per-token random value generated next to signing; pass an empty
// string when reproducing a legacy token that has no rid (verification does
// not require or interpret rid).
func newRefreshClaims(issuer, subject, jti, rid string, audience []string, now time.Time, ttl time.Duration) *refreshClaims {
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
		RID:  rid,
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
func verifyAccessToken[T any](tokenStr string, keys map[string]ed25519.PublicKey, now time.Time, issuer, audience string, leeway time.Duration) (*accessClaims[T], error) {
	if err := checkTokenString(tokenStr); err != nil {
		return nil, err
	}
	var c accessClaims[T]
	_, err := gjwt.ParseWithClaims(
		tokenStr, &c,
		eddsaKeyFunc(keys), // enforce EdDSA alg + select pub by kid; rejects HS256/RS256 confusion attacks and unknown key IDs
		parserOptions(now, issuer, audience, leeway)...,
	)
	if err != nil {
		return nil, mapJWTError(err)
	}
	if !isUUIDv7(c.Subject) {
		return nil, fmt.Errorf("%w: sub claim is not a UUID v7", ErrTokenInvalid)
	}
	if !isUUIDv7(c.ID) {
		return nil, fmt.Errorf("%w: jti claim is not a UUID v7", ErrTokenInvalid)
	}
	return &c, nil
}

// verifyRefreshToken validates the compact JWT string and returns the decoded refresh claims.
// issuer and audience are the expected "iss" and "aud" values the token must
// carry. Enforcing both defends against cross-service key reuse, where a token
// signed by the same key but issued for a different service would otherwise be
// accepted here.
// leeway is added to the expiration window to tolerate small clock skew between servers.
func verifyRefreshToken(tokenStr string, keys map[string]ed25519.PublicKey, now time.Time, issuer, audience string, leeway time.Duration) (*refreshClaims, error) {
	if err := checkTokenString(tokenStr); err != nil {
		return nil, err
	}
	var c refreshClaims
	_, err := gjwt.ParseWithClaims(
		tokenStr, &c,
		eddsaKeyFunc(keys), // enforce EdDSA alg + select pub by kid; rejects HS256/RS256 confusion attacks and unknown key IDs
		parserOptions(now, issuer, audience, leeway)...,
	)
	if err != nil {
		return nil, mapJWTError(err)
	}
	if !isUUIDv7(c.Subject) {
		return nil, fmt.Errorf("%w: sub claim is not a UUID v7", ErrTokenInvalid)
	}
	if !isUUIDv7(c.ID) {
		return nil, fmt.Errorf("%w: jti claim is not a UUID v7", ErrTokenInvalid)
	}
	return &c, nil
}

// parserOptions is the one list of claim checks both verifiers apply, so the
// access and refresh paths cannot drift apart: the refresh-path audience check
// could be deleted with the suite green before the two shared it (2026-09-25).
func parserOptions(now time.Time, issuer, audience string, leeway time.Duration) []gjwt.ParserOption {
	return []gjwt.ParserOption{
		gjwt.WithTimeFunc(func() time.Time { return now }), // inject clock so tests can freeze time
		gjwt.WithExpirationRequired(),                      // reject tokens without an exp claim
		gjwt.WithIssuedAt(),                                // reject tokens with iat in the future
		gjwt.WithIssuer(issuer),                            // token must be issued by this service
		gjwt.WithAudience(audience),                        // token must contain this audience value
		gjwt.WithLeeway(leeway),                            // tolerate small clock drift between servers
		gjwt.WithStrictDecoding(),                          // one spelling per token: no stray padding bits
	}
}

// checkTokenString bounds a token before it is parsed and keeps it to the
// compact JWS alphabet. The base64url decoder skips "\r" and "\n" and, unless
// strict, ignores the unused bits of a segment's last character, so a second
// spelling of an issued token verified; a caller that blocklists or
// deduplicates tokens by string must not see two.
func checkTokenString(tokenStr string) error {
	if len(tokenStr) > maxTokenLen {
		return fmt.Errorf("%w: length %d exceeds %d", ErrTokenOversized, len(tokenStr), maxTokenLen)
	}
	for i := 0; i < len(tokenStr); i++ {
		c := tokenStr[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("%w: byte %d is outside the base64url alphabet", ErrTokenMalformed, i)
		}
	}
	return nil
}

// eddsaKeyFunc returns a gjwt.Keyfunc that enforces EdDSA and selects the
// verification key by the token's "kid" header from keys.
//
// Holding more than one key lets a verifier accept tokens signed by a previous
// key while issuing under the current one — the overlap that makes key rotation
// zero-downtime. A token whose kid is not in the set is rejected, so the
// verifier only ever trusts keys the operator has authorised.
func eddsaKeyFunc(keys map[string]ed25519.PublicKey) gjwt.Keyfunc {
	return func(t *gjwt.Token) (any, error) {
		// Explicitly reject any algorithm that is not EdDSA.
		// Without this check an attacker could craft a token with alg=HS256
		// and sign it using the public key as the HMAC secret — a well-known
		// algorithm confusion attack that allows signature forgery.
		if _, ok := t.Method.(*gjwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("%w: unexpected alg %q", ErrTokenInvalid, t.Header["alg"])
		}
		// Select the public key by the token's kid. An unknown (or missing) kid
		// is refused — the verifier never falls back to "try every key".
		kid, _ := t.Header["kid"].(string)
		pub, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("%w: unrecognised kid %q", ErrTokenInvalid, kid)
		}
		return pub, nil
	}
}

// mapJWTError converts golang-jwt sentinel errors to our public sentinels.
// This decouples callers from the underlying library's error types, so we can
// swap or upgrade the JWT library without breaking the public API.
//
// When the underlying parser joins several failures into one error (for example
// a token that is both expired and carries the wrong issuer), the non-expiry
// failure takes precedence: a caller that treats ErrTokenExpired as "refresh
// and retry" would otherwise loop on a token whose iss is wrong, because the
// retry would carry the same wrong iss. ErrTokenExpired is therefore reserved
// for the case where expiry is the only failure.
func mapJWTError(err error) error {
	for _, sentinel := range nonExpirySentinels {
		if errors.Is(err, sentinel) {
			return ErrTokenInvalid
		}
	}
	switch {
	case errors.Is(err, gjwt.ErrTokenExpired):
		return ErrTokenExpired
	case errors.Is(err, gjwt.ErrTokenMalformed):
		return ErrTokenMalformed
	default:
		return fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
}

// nonExpirySentinels is the set of golang-jwt sentinel errors that indicate a
// claim or signature mismatch other than exp. Membership in this list raises
// the mapped error to ErrTokenInvalid even when the same input also expired,
// so a refresh-and-retry caller does not loop on a token that is wrong for a
// reason other than its lifetime.
//
// ErrTokenInvalidClaims is deliberately omitted: golang-jwt wraps every
// validation failure (including expiry) under it, so its presence does not
// distinguish a claim mismatch from an exp failure.
var nonExpirySentinels = []error{
	gjwt.ErrTokenSignatureInvalid,
	gjwt.ErrTokenUnverifiable,
	gjwt.ErrTokenInvalidIssuer,
	gjwt.ErrTokenInvalidAudience,
	gjwt.ErrTokenInvalidSubject,
	gjwt.ErrTokenInvalidId,
	gjwt.ErrTokenRequiredClaimMissing,
	gjwt.ErrTokenNotValidYet,
	gjwt.ErrTokenUsedBeforeIssued,
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

// generateRID returns 16 random bytes encoded as base64.RawURLEncoding (22
// chars, no padding) for the "rid" claim of a refresh token. The value is
// independent of the clock and any other claim; two calls in the same
// wall-clock second produce distinct values with overwhelming probability.
//
// On a crypto/rand failure generateRID wraps the error the same way generateJTI
// does, so callers can propagate it unchanged.
func generateRID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate refresh token RID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

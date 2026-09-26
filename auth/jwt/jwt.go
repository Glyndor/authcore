package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/clock"
	"github.com/Glyndor/authcore/internal/keymanager"
)

// isUUIDv7 reports whether s is a valid UUID v7 string (RFC 9562 §5.7).
// Accepts both upper and lower case — no prior normalization is required,
// removing the implicit dependency on strings.ToLower being called upstream.
//
// UUID canonical form: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx (36 chars).
func isUUIDv7(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	// Position 14: version digit must be '7'.
	if s[14] != '7' {
		return false
	}
	// Position 19: variant bits must be 8, 9, a, or b (case-insensitive).
	switch s[19] {
	case '8', '9', 'a', 'b', 'A', 'B':
	default:
		return false
	}
	// All other positions must be hex digits.
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Compile-time assertion: *JWT[struct{}] must satisfy authcore.Module.
var _ authcore.Module = (*JWT[struct{}])(nil)

// JWT is the authentication module for JSON Web Tokens.
//
// T is the application-specific type embedded in access token payloads under
// the "extra" key. Use struct{} if no custom claims are needed.
//
// Construct one instance at application startup using New and share it
// across all goroutines. JWT is safe for concurrent use after construction.
//
// A zero-value JWT[T] is unusable: HashRefreshToken returns
// ErrNotInitialised, and VerifyRefreshTokenHash returns false. New
// sets initialised as its last act, so a successful New is the only
// path to a working module.
type JWT[T any] struct {
	cfg             Config
	log             authcore.Logger
	priv            ed25519.PrivateKey
	pub             ed25519.PublicKey
	secret          []byte      // HMAC-SHA256 key for hashing refresh tokens
	kid             string      // JOSE "kid" header value, derived from the public key
	clock           clock.Clock // injected; replaced by clock.Fixed in tests
	primaryAudience string      // cfg.Audience[0] snapshotted at construction; immune to post-init mutation
	denylist        Denylist    // optional; nil means access tokens are never checked for revocation
	initialised     bool        // set by New; zero-value methods refuse to produce output

	// verifyKeys maps each accepted "kid" to its public key. It always holds
	// the current signing key and additionally any Config.PreviousPublicKeys,
	// so a verifier accepts tokens minted under a key being rotated out while
	// new tokens are signed only with the current key.
	verifyKeys map[string]ed25519.PublicKey
}

// New creates and returns a JWT module.
//
// T is the application-specific claims type embedded in access tokens.
// Use struct{} if no custom claims are needed.
//
// cfg is optional — omit it to use safe defaults (15-minute access tokens,
// 24-hour refresh tokens, EdDSA), matching the zero-config shape of the other
// modules. Pass a Config only to override lifetimes, issuer, or audience:
//
//	jwtMod, err := jwt.New[struct{}](auth)                    // defaults
//	jwtMod, err := jwt.New[MyClaims](auth, jwt.DefaultConfig()) // explicit/custom
//
// p provides the Ed25519 signing keys, the HMAC secret, the logger, and the
// timezone — all sourced from the parent AuthCore instance.
//
// New returns a wrapped ErrInvalidConfig when the provider is unusable
// (a nil interface, a Logger() or Keys() that returns nil) or when
// Keys().RefreshSecret() is not exactly 32 bytes. A module that
// successfully returned is the only path to a working JWT; every
// method on a zero value refuses to produce output.
func New[T any](p authcore.Provider, cfg ...Config) (*JWT[T], error) {
	if len(cfg) > 1 {
		return nil, fmt.Errorf("%w: at most one Config is allowed, got %d", ErrInvalidConfig, len(cfg))
	}
	if p == nil {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	logger := p.Logger()
	if logger == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	keys := p.Keys()
	if keys == nil {
		return nil, fmt.Errorf("%w: provider.Keys() returned nil", ErrInvalidConfig)
	}

	var resolved Config
	if len(cfg) > 0 {
		resolved = cfg[0]
	}
	resolved = applyDefaults(resolved)

	// Defensive copy: the caller's slice can still be mutated after New
	// returns, and the verification path reads cfg.Audience on every token.
	// A caller who reassigns an entry later would otherwise change the
	// audience of tokens the module still accepts.
	audCopy := make([]string, len(resolved.Audience))
	copy(audCopy, resolved.Audience)
	resolved.Audience = audCopy

	// Defensive copy of each previous public key: ed25519.PublicKey is a
	// []byte, so a caller wiping the slice would silently break verification
	// for tokens already signed under that key. Each entry is copied into a
	// fresh slice of the same length.
	if len(resolved.PreviousPublicKeys) > 0 {
		prevCopy := make([]ed25519.PublicKey, len(resolved.PreviousPublicKeys))
		for i, pk := range resolved.PreviousPublicKeys {
			prevCopy[i] = make(ed25519.PublicKey, len(pk))
			copy(prevCopy[i], pk)
		}
		resolved.PreviousPublicKeys = prevCopy
	}

	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	secret := keys.RefreshSecret()
	if l := len(secret); l != refreshSecretLen {
		return nil, fmt.Errorf("%w: refresh secret has wrong length: got %d, want %d",
			ErrInvalidConfig, l, refreshSecretLen)
	}

	j := &JWT[T]{
		cfg:             resolved,
		log:             logger,
		priv:            keys.PrivateKey(),
		pub:             keys.PublicKey(),
		secret:          secret,
		kid:             keys.KeyID(),
		clock:           clock.New(p.Config().Timezone),
		primaryAudience: resolved.Audience[0], // validateConfig guarantees len >= 1
		denylist:        resolved.Denylist,
	}

	// Build the verification key set: the current key plus any previous public
	// keys still in their rotation overlap. Signing always uses the current key.
	j.verifyKeys = map[string]ed25519.PublicKey{j.kid: j.pub}
	for i, prev := range resolved.PreviousPublicKeys {
		kid := keymanager.KeyID(prev)
		// A previous key registered under the current kid replaced the
		// current key in this map, and every token the module then issued
		// failed its own verification (measured 2026-09-25 with a KeyStore
		// reporting a stale kid). Refuse it at startup instead.
		if kid == j.kid {
			return nil, fmt.Errorf("%w: previous public key %d has the current signing key's id %q", ErrInvalidConfig, i, kid)
		}
		j.verifyKeys[kid] = prev
	}

	j.initialised = true

	j.log.Info("jwt: module initialised (issuer=%s, access_ttl=%s, refresh_ttl=%s, verify_keys=%d)",
		resolved.Issuer, resolved.AccessTokenTTL, resolved.RefreshTokenTTL, len(j.verifyKeys))

	return j, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (j *JWT[T]) Name() string { return "jwt" }

// CreateTokens generates a new access and refresh token pair for subject.
//
// subject is the UUID v7 that identifies the user in your system. It is stored
// in the "sub" JWT claim and returned in Claims.Subject after verification.
// Only UUID v7 is accepted (RFC 9562 §5.7); any casing is allowed — the value
// is normalised to lowercase before signing.
//
// extra holds the application-specific claims embedded in the access token
// under the "extra" key. Use struct{}{} if no custom claims are needed.
// The refresh token never carries extra claims.
//
// The returned TokenPair contains:
//
//	pair.AccessToken           — include in Authorization: Bearer on API requests
//	pair.AccessTokenExpiresAt  — send to the client to schedule proactive renewal
//	pair.RefreshToken          — store in a secure, httpOnly client-side location
//	pair.RefreshTokenExpiresAt: when this refresh token expires; each rotation issues a new one, so a session has no absolute end unless you store its start
//	pair.RefreshTokenHash      — store in your database; never store the raw token
//	pair.SessionID             — UUID v7 jti shared by both tokens; primary key for session store
//
// The same jti is carried by the access token, the refresh token, and every
// rotation of the session, so claims.TokenID after VerifyAccessToken equals
// pair.SessionID. It identifies the session, not an individual access token —
// access tokens within one session are not distinguishable by jti.
//
// The library does not persist any of these values.
func (j *JWT[T]) CreateTokens(subject string, extra T) (*TokenPair, error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	subject = strings.ToLower(subject)
	if !isUUIDv7(subject) {
		return nil, ErrInvalidSubject
	}

	jti, err := generateJTI(j.clock.Now())
	if err != nil {
		return nil, err
	}

	return j.issueTokens(subject, jti, extra)
}

// issueTokens signs a new access+refresh pair for subject using the provided jti.
// CreateTokens generates a fresh jti; RotateTokens reuses the existing session jti
// so that SessionID remains stable for the lifetime of the session.
func (j *JWT[T]) issueTokens(subject, jti string, extra T) (*TokenPair, error) {
	now := j.clock.Now()

	// golang-jwt truncates the exp claim to whole seconds. Apply the same
	// truncation here so AccessTokenExpiresAt reports exactly what the signed
	// claim says; a sub-second TTL must not round in the operator's view.
	accessExpiresAt := now.Add(j.cfg.AccessTokenTTL).Truncate(time.Second)
	refreshExpiresAt := now.Add(j.cfg.RefreshTokenTTL).Truncate(time.Second)

	// ----- Access token -----
	accessToken, err := signToken(newAccessClaims(j.cfg.Issuer, subject, jti, j.cfg.Audience, extra, now, j.cfg.AccessTokenTTL), j.priv, j.kid)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}
	if n := len(accessToken); n > maxTokenLen {
		// Enforce the same cap the verifier applies. A token that exceeds the
		// limit would verify as ErrTokenOversized, so refuse at issuance with
		// a message that names the limit and the actual length instead of
		// letting the operator discover it on the next request.
		return nil, fmt.Errorf("%w: length %d exceeds %d byte limit (issuer=%d, audience=%d)",
			ErrTokenOversized, n, maxTokenLen, len(j.cfg.Issuer), sumLen(j.cfg.Audience))
	}

	// ----- Refresh token (no extra) -----
	// Each refresh token gets a fresh random rid here, next to signing, so
	// newRefreshClaims stays a pure constructor.
	rid, err := generateRID()
	if err != nil {
		return nil, err
	}
	refreshToken, err := signToken(newRefreshClaims(j.cfg.Issuer, subject, jti, rid, j.cfg.Audience, now, j.cfg.RefreshTokenTTL), j.priv, j.kid)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}
	if n := len(refreshToken); n > maxTokenLen {
		return nil, fmt.Errorf("%w: length %d exceeds %d byte limit (issuer=%d, audience=%d)",
			ErrTokenOversized, n, maxTokenLen, len(j.cfg.Issuer), sumLen(j.cfg.Audience))
	}

	j.log.Debug("jwt: token pair issued (sub=%s, jti=%s)", subject, jti)

	return &TokenPair{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
		RefreshTokenHash:      computeHMAC(refreshToken, j.secret),
		SessionID:             jti,
	}, nil
}

// sumLen returns the sum of len(entry) across entries. Used to surface the
// total audience bytes in an ErrTokenOversized message.
func sumLen(entries []string) int {
	n := 0
	for _, e := range entries {
		n += len(e)
	}
	return n
}

// VerifyAccessToken parses and validates an access token string.
//
// On success it returns the verified Claims extracted from the token payload,
// including the application-specific Extra fields.
// On failure it returns one of the following sentinel errors:
//
//	jwt.ErrTokenExpired   — exp claim is in the past
//	jwt.ErrTokenInvalid   — signature invalid, unsupported algorithm,
//	                        or iss/aud claim does not match Config
//	jwt.ErrTokenMalformed — not a valid three-part JWT string
//	jwt.ErrWrongTokenType — token is a refresh token, not an access token
//	jwt.ErrTokenRevoked   — a configured Denylist reports the token's session revoked
//
// If a configured Denylist returns its own error (transport, timeout, parse),
// the error is wrapped with the store's error verbatim and returned through
// this call. There is no sentinel for store failures; treat any error that
// is not ErrTokenRevoked as an internal problem with the denylist itself.
//
// Use errors.Is for error inspection:
//
//	claims, err := jwtMod.VerifyAccessToken(token)
//	if errors.Is(err, jwt.ErrTokenExpired) { ... }
//
// When a Denylist is configured (Config.Denylist), the revocation lookup runs
// under a background context bounded by a default 5-second timeout so a slow or
// hung store cannot block the verifying goroutine forever. Use
// VerifyAccessTokenContext to pass your own context (recommended for a
// network-backed denylist, e.g. to inherit the request deadline).
func (j *JWT[T]) VerifyAccessToken(token string) (*Claims[T], error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	if j.denylist == nil {
		return j.VerifyAccessTokenContext(context.Background(), token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDenylistTimeout)
	defer cancel()
	return j.VerifyAccessTokenContext(ctx, token)
}

// VerifyAccessTokenContext is VerifyAccessToken with an explicit context that
// is passed to the configured Denylist (if any). The context bounds only the
// revocation lookup; signature and expiry checks are local and never block.
func (j *JWT[T]) VerifyAccessTokenContext(ctx context.Context, token string) (*Claims[T], error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	c, err := verifyAccessToken[T](token, j.verifyKeys, j.clock.Now(), j.cfg.Issuer, j.primaryAudience, j.cfg.ClockSkewLeeway)
	if err != nil {
		return nil, err
	}
	if c.Type != tokenTypeAccess {
		return nil, ErrWrongTokenType
	}
	// Revocation is checked last — only an otherwise-valid access token is worth
	// a denylist lookup, so a garbage or expired token never reaches the store.
	if j.denylist != nil {
		revoked, err := j.denylist.IsRevoked(ctx, c.ID)
		if err != nil {
			return nil, fmt.Errorf("jwt: denylist lookup: %w", err)
		}
		if revoked {
			return nil, ErrTokenRevoked
		}
	}
	return accessClaimsToClaims(c), nil
}

// HashRefreshToken returns the HMAC-SHA256 hex digest of the given token
// string using the library's managed refresh secret.
//
// Use this to derive the database lookup key before calling RotateTokens:
//
//	hash, err := jwtMod.HashRefreshToken(clientToken)
//	if err != nil { return serverError() }
//	row, err := db.FindByHash(hash)
//	if err != nil { return http.StatusUnauthorized }
//	newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
//
// HashRefreshToken returns ErrNotInitialised on a zero-value JWT[T].
// The signature changed from `string` to `(string, error)` so a module
// that was never constructed by New cannot emit a hash under an empty
// HMAC secret.
func (j *JWT[T]) HashRefreshToken(token string) (string, error) {
	if !j.initialised {
		return "", ErrNotInitialised
	}
	return computeHMAC(token, j.secret), nil
}

// VerifyRefreshTokenHash reports whether token produces the same HMAC-SHA256
// digest as storedHash using a constant-time comparison to prevent timing attacks.
//
// Call this instead of a plain string equality check when validating a client's
// refresh token against the hash stored in your database:
//
//	if !jwtMod.VerifyRefreshTokenHash(clientToken, row.RefreshTokenHash) {
//	    return http.StatusUnauthorized
//	}
//	newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
//
// VerifyRefreshTokenHash returns false on a zero-value JWT[T]: a module
// with no HMAC secret cannot verify anything, and answering true would
// let a caller mistake "no key was used" for "the key matched".
func (j *JWT[T]) VerifyRefreshTokenHash(token, storedHash string) bool {
	if !j.initialised {
		return false
	}
	computed := computeHMAC(token, j.secret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

// RotateTokens verifies refreshToken, then generates and returns a new
// token pair for the same subject with fresh extra claims.
//
// Because the refresh token does not carry application-specific data, the
// caller must supply updated extra claims (typically re-fetched from the
// database at rotation time).
//
// Each refresh token carries a random rid, so two tokens of one session never
// compare equal, whatever the clock says.
//
// The SessionID (jti) is preserved across rotations — only the token strings
// and their expiry times change. This means the caller's session record
// primary key remains stable for the entire session lifetime.
//
// After a successful rotation, the old refresh token MUST be considered
// invalid. The application must replace the stored hash atomically:
//
//	db.ReplaceRefreshHash(oldHash, newPair.RefreshTokenHash)
//
// This function validates the token's signature and expiry but does NOT check
// whether the hash exists in a database — that is the application's responsibility
// and must happen before calling RotateTokens.
//
// Returns the same verification errors as VerifyAccessToken (a refresh token
// goes through the same signature / expiry / iss / aud pipeline), including
// ErrTokenRevoked: when a Denylist is configured, a revoked session cannot be
// rotated. Before 2026-09-25 it could, and the rotated access token verified
// again as soon as the denylist entry lapsed. The lookup runs under the same
// default 5-second timeout as VerifyAccessToken; use RotateTokensContext to
// pass your own context. It can also fail during signing, for example if the JSON encoder refuses
// a NaN or Inf in extra (rotating JWT[float64] with math.NaN() returns
// "sign access token: json: unsupported value: NaN"); verifyAccessToken
// cannot fail this way because it never serialises extra.
func (j *JWT[T]) RotateTokens(refreshToken string, extra T) (*TokenPair, error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	if j.denylist == nil {
		return j.RotateTokensContext(context.Background(), refreshToken, extra)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDenylistTimeout)
	defer cancel()
	return j.RotateTokensContext(ctx, refreshToken, extra)
}

// RotateTokensContext is RotateTokens with an explicit context that is passed
// to the configured Denylist (if any). The context bounds only the revocation
// lookup.
func (j *JWT[T]) RotateTokensContext(ctx context.Context, refreshToken string, extra T) (*TokenPair, error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	c, err := verifyRefreshToken(refreshToken, j.verifyKeys, j.clock.Now(), j.cfg.Issuer, j.primaryAudience, j.cfg.ClockSkewLeeway)
	if err != nil {
		return nil, err
	}
	if c.Type != tokenTypeRefresh {
		return nil, ErrWrongTokenType
	}
	if j.denylist != nil {
		revoked, err := j.denylist.IsRevoked(ctx, c.ID)
		if err != nil {
			return nil, fmt.Errorf("jwt: denylist lookup: %w", err)
		}
		if revoked {
			return nil, ErrTokenRevoked
		}
	}

	j.log.Debug("jwt: rotating token (sub=%s, jti=%s)", c.Subject, c.ID)

	return j.issueTokens(c.Subject, c.ID, extra)
}

package jwt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/denylist"
	"github.com/Glyndor/authcore/auth/jwt/internal/issue"
	"github.com/Glyndor/authcore/auth/jwt/internal/refreshhash"
	"github.com/Glyndor/authcore/auth/jwt/internal/rotation"
	"github.com/Glyndor/authcore/auth/jwt/internal/verify"
	"github.com/Glyndor/authcore/internal/clock"
	"github.com/Glyndor/authcore/internal/keymanager"
)

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
// (a nil interface, a Logger() or Keys() that returns nil), when the
// provider's Ed25519 key pair fails keymanager.ValidateMaterial (nil or
// short private key, nil public key, a public key from another pair, an
// internally inconsistent private key, or a refresh secret that is not
// exactly 32 bytes). A module that successfully returned is the only
// path to a working JWT; every method on a zero value refuses to produce
// output.
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

	// Hold a caller-written Provider to the rules the key stores apply.
	// Measured on 2026-09-27 against v1.18.1, when only the secret was
	// checked here: a nil or 10-byte private key passed New and CreateTokens
	// panicked ("slice bounds out of range [32:0]" and "[32:10]"), and a nil
	// public key or one from another pair passed New and every token issued
	// failed VerifyAccessToken with "jwt: token is invalid".
	if err := keymanager.ValidateMaterial(keys.PrivateKey(), keys.PublicKey(), secret); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	// The kid travels in a JSON header, and encoding/json writes every invalid
	// UTF-8 byte as U+FFFD. A Provider whose id holds such a byte would sign
	// tokens whose header names a different id from the one in the key set, so
	// every token it issued would fail its own verification.
	if !utf8.ValidString(keys.KeyID()) {
		return nil, fmt.Errorf("%w: provider key id is not valid UTF-8", ErrInvalidConfig)
	}

	j := &JWT[T]{
		cfg:             resolved,
		log:             logger,
		priv:            keys.PrivateKey(),
		pub:             keys.PublicKey(),
		secret:          bytes.Clone(secret),
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
	r, err := issue.Create(j.issueParams(), j.clock.Now(), subject, extra)
	if err != nil {
		return nil, err
	}
	return (*TokenPair)(r), nil
}

// issueParams snapshots the signing policy the issue package applies.
func (j *JWT[T]) issueParams() issue.Params {
	return issue.Params{
		Priv:       j.priv,
		KID:        j.kid,
		Issuer:     j.cfg.Issuer,
		Audience:   j.cfg.Audience,
		AccessTTL:  j.cfg.AccessTokenTTL,
		RefreshTTL: j.cfg.RefreshTokenTTL,
		Secret:     j.secret,
		Log:        j.log,
	}
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
	ctx, cancel := denylist.Context(j.denylist)
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
	c, err := verify.Access[T](ctx, j.verifyParams(), j.clock.Now(), token)
	if err != nil {
		return nil, err
	}
	return accessClaimsToClaims(c), nil
}

// verifyParams snapshots the verification policy the verify package applies.
func (j *JWT[T]) verifyParams() verify.Params {
	return verify.Params{
		Keys:     j.verifyKeys,
		Issuer:   j.cfg.Issuer,
		Audience: j.primaryAudience,
		Leeway:   j.cfg.ClockSkewLeeway,
		Denylist: j.denylist,
	}
}

// accessClaimsToClaims converts internal claims.Access to the public Claims type.
func accessClaimsToClaims[T any](c *claims.Access[T]) *Claims[T] {
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
// HashRefreshToken returns ErrNotInitialised on a zero-value or nil JWT[T].
// The signature changed from `string` to `(string, error)` so a module
// that was never constructed by New cannot emit a hash under an empty
// HMAC secret.
func (j *JWT[T]) HashRefreshToken(token string) (string, error) {
	if j == nil || !j.initialised {
		return "", ErrNotInitialised
	}
	return refreshhash.Compute(token, j.secret), nil
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
// VerifyRefreshTokenHash returns false on a zero-value or nil JWT[T]: a module
// with no HMAC secret cannot verify anything, and answering true would
// let a caller mistake "no key was used" for "the key matched".
func (j *JWT[T]) VerifyRefreshTokenHash(token, storedHash string) bool {
	if j == nil || !j.initialised {
		return false
	}
	return refreshhash.Equal(token, storedHash, j.secret)
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
	ctx, cancel := denylist.Context(j.denylist)
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
	r, err := rotation.Rotate(ctx, j.verifyParams(), j.issueParams(), j.clock.Now(), refreshToken, extra)
	if err != nil {
		return nil, err
	}
	return (*TokenPair)(r), nil
}

package jwt

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"unicode/utf8"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/clock"
	"github.com/Glyndor/authcore/internal/keymanager"
	"github.com/Glyndor/authcore/internal/nilvalue"
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
	if nilvalue.IsNil(p) {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	logger := p.Logger()
	if logger == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	keys := p.Keys()
	if nilvalue.IsNil(keys) {
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

	// The key slices are copied like the secret: the provider's accessors
	// return its own memory, and a caller clearing them after use must not
	// change what this module signs and verifies with.
	j := &JWT[T]{
		cfg:             resolved,
		log:             logger,
		priv:            bytes.Clone(keys.PrivateKey()),
		pub:             bytes.Clone(keys.PublicKey()),
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

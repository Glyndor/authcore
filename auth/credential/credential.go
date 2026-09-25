// Package credential mints and verifies single-use credential tokens for
// authcore.
//
// # What it is for
//
// Password resets and account activations are the two most security
// sensitive emails an application ever sends. The token that powers
// each of them has to be high-entropy, single-use, time-bounded, and
// bound to the user and the flow it was minted for. Without that
// binding, a caller who keeps one table for both flows has a
// cross-flow confusion bug, and one who looks up by token rather than
// by user has an account mixup. This module makes those mistakes
// impossible from the credential side: it mints the token, hands the
// raw value back once for the email link and a keyed hash for the
// caller to store, and verifies a presented token against the stored
// hash. The module stores nothing.
//
//	auth, _ := authcore.New(authcore.DefaultConfig())
//	cred, _ := credential.New(auth)
//
//	// Issue: put Token in the email link, persist Hash and issuedAt.
//	issued, _ := cred.Issue("reset", "alice@example.com")
//	sendEmail(alice, "?token="+url.QueryEscape(issued.Token))
//	db.StoreResetToken(alice.ID, issued.Hash, time.Now())
//
//	// Verify: same purpose and subject, before TTL, with single-use.
//	err := cred.Verify("reset", "alice@example.com",
//	    presented, storedHash, storedAt)
//	switch {
//	case errors.Is(err, credential.ErrExpired):
//	    return genericError() // "link invalid or expired"
//	case errors.Is(err, credential.ErrInvalidCredential):
//	    return genericError() // same message; never reveal which it was
//	case err != nil:
//	    return serverError()
//	}
//	db.DeleteResetToken(alice.ID) // single use, in the same transaction
//
// # What is fixed and what is open
//
// The cryptographic layer is closed: token entropy, HMAC-SHA256 with the
// library-managed pepper, base64-URL encoding, constant-time comparison,
// and the purpose || subject || token binding into the stored hash are
// all fixed. Weakening any of these produces a credential a stolen
// email can be spent against the wrong user or the wrong flow.
//
// The policy layer is open with secure defaults: the TTL (how long a
// token stays valid) is configurable within a 1-nanosecond-to-24-hour
// range, enforced by validateConfig. See docs/configuration.md for the
// principle.
package credential

import (
	"crypto/hmac"
	"crypto/rand" //nolint:gosec // CSPRNG draws for tokens
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/clock"
)

// Compile-time assertion: *Credential must satisfy authcore.Module.
var _ authcore.Module = (*Credential)(nil)

const (
	tokenLen   = 32 // 256 bits of CSPRNG output per token
	futureSkew = time.Minute
)

// Credential is the credential module.
//
// Construct one instance at application startup using New and share it
// across goroutines. Credential is safe for concurrent use after
// construction.
//
// It carries configuration only. Issue returns everything an issuance
// produces, so the module is safe to share across goroutines and never
// holds a raw token.
type Credential struct {
	cfg    Config
	log    authcore.Logger
	secret []byte      // HMAC-SHA256 pepper, sourced from the parent AuthCore
	clock  clock.Clock // injected; replaced by clock.Fixed in tests

	initialised bool // set by New; zero-value methods refuse to run
}

// refreshSecretLen is the byte length New demands from
// Keys().RefreshSecret(). The HMAC-SHA256 pepper must match across
// every server that shares an installation; a short or absent secret
// would silently weaken every token's stored hash.
const refreshSecretLen = 32

// The module holds no per-issue state on purpose. An earlier draft kept the
// most recent Token and Hash on this struct, which made two concurrent Issue
// calls a data race (the race detector flags it) and left the raw token, the
// one secret the caller must show exactly once, alive in memory for as long
// as the module. Issue returns everything the caller needs.

// Issued is the result of Issue.
//
// Show Token to the user EXACTLY ONCE, typically by embedding it in a
// single-use email link. Persist Hash and the issuance timestamp together;
// pass them back to Verify at redemption time. The mapping between Token
// and Hash is 1:1 and irreversible: Hash cannot be inverted to recover
// Token.
type Issued struct {
	// Token is the raw token. Put this in the email link; show it once.
	Token string
	// Hash is what the caller stores. It is a keyed HMAC-SHA256 hex digest
	// that binds Token to the purpose and subject it was minted for.
	Hash string
}

// New creates a Credential module.
//
// cfg is optional. Omit it to apply the safe default (TTL=1 hour).
// Passing Config{} explicitly is treated as a 0 TTL and rejected as
// ErrInvalidConfig; the 1-hour default is reachable only by omitting the
// argument, or by passing a Config with an explicit positive TTL:
//
//	cred, err := credential.New(auth)                                 // 1h default
//	cred, err := credential.New(auth, credential.Config{TTL: 15 * time.Minute})
//	cred, err := credential.New(auth, credential.Config{})            // ErrInvalidConfig: TTL=0
//
// The module reads the parent AuthCore's logger, refresh secret, and
// timezone; it generates no key material of its own.
//
// New returns a wrapped ErrInvalidConfig when the provider is
// unusable (a nil interface, a Logger() or Keys() that returns nil)
// or when Keys().RefreshSecret() is not exactly 32 bytes.
func New(p authcore.Provider, cfg ...Config) (*Credential, error) {
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
		resolved = applyDefaults(cfg[0])
	} else {
		resolved = DefaultConfig()
	}
	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	secret := keys.RefreshSecret()
	if l := len(secret); l != refreshSecretLen {
		return nil, fmt.Errorf("%w: refresh secret has wrong length: got %d, want %d",
			ErrInvalidConfig, l, refreshSecretLen)
	}

	c := &Credential{
		cfg:         resolved,
		log:         logger,
		secret:      secret,
		clock:       clock.New(p.Config().Timezone),
		initialised: true,
	}
	c.log.Info("credential: module initialised (ttl=%s)", resolved.TTL)
	return c, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (c *Credential) Name() string { return "credential" }

// Issue mints a fresh credential token bound to purpose and subject, and
// returns the raw token (for the email link) alongside the hash (for
// storage). Both purpose and subject are required, because an unbound
// token is
// the failure this module exists to prevent.
//
// The returned Issued is the only place the raw token appears. The module
// keeps no copy: it is safe to call from several goroutines at once, and
// the token does not outlive what the caller does with it.
//
// Errors:
//
//	credential.ErrEmptyPurpose - purpose is ""
//	credential.ErrEmptySubject - subject is ""
//	credential.ErrNotInitialised - the receiver is a zero value
func (c *Credential) Issue(purpose, subject string) (*Issued, error) {
	if !c.initialised {
		return nil, ErrNotInitialised
	}
	if purpose == "" {
		return nil, ErrEmptyPurpose
	}
	if subject == "" {
		return nil, ErrEmptySubject
	}

	tokenBytes := make([]byte, tokenLen)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("credential: generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := c.computeHash(purpose, subject, token)

	c.log.Debug("credential: issued (purpose=%q, subject=%q)", purpose, subject)

	return &Issued{Token: token, Hash: hash}, nil
}

// Verify checks a presented token against a stored hash for the given
// purpose and subject, with expiry enforced against issuedAt.
//
// purpose and subject must be the same strings that were passed to Issue.
// A mismatched purpose or subject produces a different hash and therefore
// a clean failure, so the module cannot redeem a "reset" token as an
// "activate" token, nor one for alice@example.com as one for bob@example.com.
//
// issuedAt must be the timestamp the caller stored alongside the hash at
// Issue time. The token is rejected as expired when:
//
//   - clock.Now() is more than Config.TTL past issuedAt, or
//   - issuedAt is more than one minute in the future (a clock that has
//     run more than a minute ahead must not mint a token that looks
//     future-dated to a verifier on the correct time).
//
// Only the future side is guarded. A clock that runs backwards after
// issuance extends a token's effective life: issuing at 12:00 with a
// one-hour TTL, hitting Verify at 13:01 with the expired-token error,
// and rolling the clock back to 12:59 makes the token verify again,
// because elapsed (59 minutes) is once more inside the TTL window.
// The full TTL is the upper bound on how much backwards drift the
// verifier will absorb. Treat your server clock as part of the trust
// boundary for this module.
//
// Errors:
//
//	credential.ErrInvalidCredential - token does not match the stored hash
//	credential.ErrExpired           - hash matched but issuedAt is outside
//	                                 the TTL window
//
// The caller MUST return the same generic message ("link invalid or
// expired") for both errors. Distinguishing them tells an attacker that a
// token existed. Compare, then check expiry; both run on every call so
// the expiry check itself does not leak "token existed vs. token did
// not exist". The constant-time comparison still does: subtle's
// ConstantTimeCompare returns 0 immediately when its arguments differ
// in length, so an empty (or otherwise malformed) storedHash returns
// before any byte of the candidate is touched, while a 64-character
// storedHash compares all 64 bytes. The wall-clock time of Verify
// therefore reveals whether storedHash is the 64-hex-char shape
// computeHash produces, which corresponds to "the row exists and
// carries a real hash", not just "a token existed". The caller should
// not rely on Verify to hide that distinction.
func (c *Credential) Verify(purpose, subject, token, storedHash string, issuedAt time.Time) error {
	if !c.initialised {
		return ErrNotInitialised
	}
	// Always recompute the hash and run the constant-time comparison,
	// even if a later check would reject the call anyway. The
	// comparison runs before the expiry check on purpose; see the
	// function comment for the timing property this preserves (and the
	// one it does not).
	candidate := c.computeHash(purpose, subject, token)
	matched := subtle.ConstantTimeCompare([]byte(candidate), []byte(storedHash)) == 1

	elapsed := c.clock.Now().Sub(issuedAt)
	expired := elapsed > c.cfg.TTL || elapsed < -futureSkew

	if !matched {
		return ErrInvalidCredential
	}
	if expired {
		return ErrExpired
	}
	return nil
}

// computeHash returns the keyed HMAC-SHA256 hex digest of purpose, subject
// and token, each length-prefixed with a big-endian uint32.
//
// The length prefix is what makes the encoding unambiguous, and it is not
// interchangeable with a separator byte. An earlier draft joined the fields
// with a 0x00 byte, which works only while no field can contain that byte,
// and a Go string can: (purpose="a\x00b", subject="c") and (purpose="a",
// subject="b\x00c") hashed identically, so a caller whose subject came from
// untrusted input could redeem a token minted for a different pair. That is
// the exact property this module exists to provide. Prefixing by length
// depends on no assumption about the contents.
//
// Both Issue and Verify call through here, so a mismatched purpose or
// subject at Verify time produces a different candidate hash and a clean
// comparison failure.
func (c *Credential) computeHash(purpose, subject, token string) string {
	mac := hmac.New(sha256.New, c.secret)
	writeField(mac, purpose)
	writeField(mac, subject)
	writeField(mac, token)
	return hex.EncodeToString(mac.Sum(nil))
}

// writeField writes s to h prefixed by its length as a big-endian uint32.
func writeField(h hash.Hash, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

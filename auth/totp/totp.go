// Package totp provides Time-based One-Time Password (TOTP, RFC 6238)
// authentication for authcore.
//
// TOTP is the algorithm behind the six-digit rotating codes shown by
// Google Authenticator, 1Password, Authy and every other authenticator
// app. authcore enrolls a user by minting a high-entropy shared secret,
// returns an otpauth:// URI that the user's app scans as a QR code, and
// verifies the codes the user subsequently produces - all in constant
// time, with replay protection that the caller wires through a
// StepRecorder.
//
//	auth, _   := authcore.New(authcore.DefaultConfig())
//	totpMod, _ := totp.New(auth)
//
//	// Enroll - show the URI to the user, store secret + recovery hashes.
//	enr, _ := totpMod.Enroll("alice@example.com")
//	db.StoreTOTP(userID, enr.Secret, enr.RecoveryHashes)
//
//	// Verify - the recorder holds the "last accepted step" for this
//	// enrollment and advances it atomically. A nil recorder is a
//	// programming error and is refused with ErrStepRecorderRequired.
//	err := totpMod.Verify(ctx, secret, presented, db.Recorder(userID))
//	if errors.Is(err, totp.ErrCodeReused) {
//	    log.Warn("totp: replay attempt (user=%s)", userID)
//	    return http.StatusUnauthorized
//	}
//	if err != nil { return http.StatusUnauthorized }
//
// # What is fixed and what is open
//
// The cryptographic layer is closed: HMAC-SHA1, 30-second time step,
// 6-digit codes, 20-byte secrets and constant-time comparison are the
// interoperability baseline - every widely-used authenticator app
// ignores the algorithm, digits and period parameters of an otpauth://
// URI and assumes SHA1/6/30. A configurable value here produces an
// enrollment that works in your test environment and locks the user out
// on their phone.
//
// The policy layer is open with secure defaults: the clock-skew window
// (SkewSteps), the number of recovery codes (RecoveryCodeCount) and the
// issuer label (Issuer) can be tuned per deployment without weakening
// the security floor. See docs/configuration.md for the principle.
//
// # Replay protection
//
// A TOTP code stays valid for its whole 30-second window, so an attacker
// who observes one can replay it until the window closes. Verify stops
// that by handing the matched step to a StepRecorder that advances the
// stored step only when it is strictly greater than the one on file.
// Compare and store commit together inside the recorder (a conditional
// UPDATE is the model), so two concurrent submissions of the same code
// cannot both succeed. VerifyStep, the low-level primitive, refuses
// nothing on its own: a caller that passes 0 gets no replay refusal at
// all, which is the documented hazard that forces Verify to require a
// recorder.
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/rand" //nolint:gosec // CSPRNG draws for secrets and recovery codes
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline; SHA1 collision attacks do not apply to HMAC
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/clock"
)

// Compile-time assertion: *TOTP must satisfy authcore.Module.
var _ authcore.Module = (*TOTP)(nil)

// Cryptographic constants fixed by RFC 6238 §1.2 and the otpauth
// interoperability baseline. They are intentionally not configurable.
const (
	digits    = 6  // every authenticator app assumes this
	timeStep  = 30 // 30-second window
	secretLen = 20 // 160-bit shared secret per RFC 4226 §4 R1
	algoSHA1  = "SHA1"
)

// recoveryLen is the byte length of a single recovery code CSPRNG draw.
// 10 bytes = 80 bits, formatted as two base32 groups of 8 chars joined
// by a hyphen (e.g. "ABCD1234-EFGH5678").
const recoveryLen = 10

// Enrollment is the result of Enroll.
//
// Show Secret, URI and RecoveryCodes to the user EXACTLY ONCE - none is
// recoverable afterwards. Persist Secret (the lookup key, base32) and
// RecoveryHashes (the verification material). Never persist the raw
// RecoveryCodes; they must not survive the enrollment request.
type Enrollment struct {
	// Secret is the shared secret in base32 (no padding), the form
	// authenticator apps accept for manual entry.
	Secret string
	// URI is the otpauth:// URI to encode in the QR code the user scans.
	URI string
	// RecoveryCodes are the raw recovery codes, formatted as two base32
	// groups of 8 chars separated by a hyphen. Hand them to the user
	// ONCE; the caller must delete them from memory after display.
	RecoveryCodes []string
	// RecoveryHashes are the corresponding HMAC-SHA256 digests of the
	// raw codes (peppered with the library's refresh secret). Store
	// these and pass them to VerifyRecoveryCode. The mapping is
	// positional: RecoveryHashes[i] is the hash of RecoveryCodes[i].
	RecoveryHashes []string
}

// TOTP is the TOTP module.
//
// Construct one instance at application startup using New and share it
// across goroutines. TOTP is safe for concurrent use after construction.
type TOTP struct {
	cfg    Config
	log    authcore.Logger
	secret []byte      // HMAC-SHA256 pepper for recovery-code hashing
	clock  clock.Clock // injected; replaced by clock.Fixed in tests
	// initialised is set by New as its last act. A zero-value TOTP hashed
	// recovery codes under an empty key, which anyone can compute, until
	// 2026-09-25; every method now refuses on it.
	initialised bool
}

// New creates a TOTP module.
//
// cfg is optional - omit it, or pass a zero-value Config, to apply the
// safe defaults (SkewSteps=1, RecoveryCodeCount=10, Issuer="").
//
//	totpMod, err := totp.New(auth)                      // defaults
//	totpMod, err := totp.New(auth, totp.DefaultConfig()) // explicit
//	totpMod, err := totp.New(auth, totp.Config{Issuer: "Acme"})
//
// SkewSteps is a pointer: nil (the zero Config) means the default of one
// step either side, and totp.Int(0) means only the current step. New copies
// the value, so changing the caller's int afterwards has no effect.
//
// The provider must supply a 32-byte refresh secret, which keys the
// recovery-code hashes.
//
// The module reads the parent AuthCore's logger and refresh secret; it
// generates no key material of its own.
func New(p authcore.Provider, cfg ...Config) (*TOTP, error) {
	if len(cfg) > 1 {
		return nil, fmt.Errorf("%w: at most one Config is allowed, got %d", ErrInvalidConfig, len(cfg))
	}
	if p == nil {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	if p.Logger() == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	keys := p.Keys()
	if keys == nil {
		return nil, fmt.Errorf("%w: provider.Keys() returned nil", ErrInvalidConfig)
	}
	// An absent or short secret hashed recovery codes under a key anyone can
	// compute; apikey, jwt, field and credential refused it since #425.
	secret := keys.RefreshSecret()
	if l := len(secret); l != refreshSecretLen {
		return nil, fmt.Errorf("%w: refresh secret has wrong length: got %d, want %d", ErrInvalidConfig, l, refreshSecretLen)
	}
	var resolved Config
	if len(cfg) > 0 {
		resolved = applyDefaults(cfg[0])
	} else {
		resolved = DefaultConfig()
	}
	// Copy SkewSteps before validating it. New kept the caller's pointer, so a
	// write through it after New widened the window past maxSkewSteps: at
	// 1,000,000, four of five arbitrary codes verified (measured 2026-09-25).
	resolved.SkewSteps = Int(*resolved.SkewSteps)
	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	t := &TOTP{
		cfg:    resolved,
		log:    p.Logger(),
		secret: secret,
		clock:  clock.New(p.Config().Timezone),
	}
	t.initialised = true
	t.log.Info("totp: module initialised (skew=%d, recovery_codes=%d, issuer=%q)",
		*resolved.SkewSteps, resolved.RecoveryCodeCount, resolved.Issuer)
	return t, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (t *TOTP) Name() string { return "totp" }

// Enroll generates a fresh shared secret for accountName, an otpauth://
// URI the user's app can scan as a QR code, and a set of recovery codes.
// Returned values must be shown to the user ONCE (URI as QR, RecoveryCodes
// as a printable list). An empty Config.Issuer means the URI is built
// without the issuer parameter and the label, and the authenticator
// displays only the account name.
func (t *TOTP) Enroll(accountName string) (*Enrollment, error) {
	if t == nil || !t.initialised {
		return nil, ErrNotInitialised
	}
	secretBytes, err := randomBytes(secretLen)
	if err != nil {
		return nil, fmt.Errorf("totp: generate secret: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	uri, err := buildURI(t.cfg.Issuer, accountName, secret)
	if err != nil {
		return nil, fmt.Errorf("totp: build uri: %w", err)
	}

	rawCodes := make([]string, t.cfg.RecoveryCodeCount)
	hashes := make([]string, t.cfg.RecoveryCodeCount)
	for i := 0; i < t.cfg.RecoveryCodeCount; i++ {
		buf, err := randomBytes(recoveryLen)
		if err != nil {
			return nil, fmt.Errorf("totp: generate recovery code: %w", err)
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
		formatted := formatRecoveryCode(encoded)
		rawCodes[i] = formatted
		// hashRecoveryCode normalises on the way in, so the stored
		// hash matches what VerifyRecoveryCode computes regardless
		// of how the user typed the code.
		hashes[i] = t.hashRecoveryCode(formatted)
	}

	t.log.Debug("totp: enrolled (account=%q, recovery_codes=%d)", accountName, len(rawCodes))

	return &Enrollment{
		Secret:         secret,
		URI:            uri,
		RecoveryCodes:  rawCodes,
		RecoveryHashes: hashes,
	}, nil
}

// VerifyStep checks candidate code against secret for the current time
// step and the configured skew window. It returns the time step the
// code matched on success.
//
// VerifyStep is the low-level primitive. It does not read or write any
// storage: replay refusal is purely a function of the lastUsedStep the
// caller passes in. That is enough for one verifier, but two verifiers
// running against the same enrollment must not call VerifyStep with the
// lastUsedStep they read from the store - they will race, and a single
// stolen code can be accepted by both. The recorder-backed Verify
// exists to close that race: it delegates the compare-and-advance to
// storage that can make the two operations atomic.
//
// # lastUsedStep and the documented hazard
//
// lastUsedStep is the highest step VerifyStep has accepted for this
// enrollment, or 0 for the first call. Any step at or below it is
// refused with ErrCodeReused - even if the code is otherwise valid - so
// passing the value the store held the last time VerifyStep returned
// nil is the single thing that turns a successful verify into a
// single-use verify.
//
// A caller who always passes 0 has NO replay refusal: every code that
// matches the current window is accepted, including codes the user has
// already used. That is correct for a first verification, and the
// documented wrong behaviour for every other. Verify does not expose
// this shape: its signature requires a StepRecorder, and it refuses a
// nil one with ErrStepRecorderRequired at the first call.
//
// Errors:
//
//	totp.ErrInvalidCode   - six digits, matches no step in the window
//	totp.ErrMalformedCode - not six decimal digits
//	totp.ErrInvalidSecret - secret is not base32, or is not 20 bytes decoded
//	totp.ErrCodeReused    - matches a step at or below lastUsedStep
func (t *TOTP) VerifyStep(secret, code string, lastUsedStep uint64) (uint64, error) {
	if t == nil || !t.initialised {
		return 0, ErrNotInitialised
	}
	if !isSixDigits(code) {
		return 0, ErrMalformedCode
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, err
	}

	currentStep := uint64(t.clock.Now().Unix()) / timeStep

	// Scan every step in the window. Never early-return on the first
	// match: that would let an attacker distinguish "matched the
	// current step" from "matched a neighbouring step" by timing.
	var matchedStep uint64
	var matched byte
	skew := uint64(*t.cfg.SkewSteps)
	// When currentStep is smaller than skew the lower bound wraps to a
	// value near the top of the uint64 range, which is above the upper
	// bound, so the loop body does not run and VerifyStep reports no
	// match. That needs the clock to read within skew steps of the Unix
	// epoch, so it cannot happen in production, and reporting no match
	// is the safe answer when it does. There is no negative step: this
	// is uint64.
	for step := currentStep - skew; step <= currentStep+skew; step++ {
		if stepMatches(step, key, code) {
			matched = 1
			matchedStep = step
		}
	}

	if matched == 0 {
		return 0, ErrInvalidCode
	}
	if matchedStep <= lastUsedStep {
		return 0, ErrCodeReused
	}
	return matchedStep, nil
}

// Verify is the recording entry point: it asks VerifyStep for the matched
// step and, only when the code is acceptable, hands that step to rec for
// an atomic compare-and-advance. The recorder, not this function, owns
// durability and the cross-process guarantee that two concurrent
// submissions of the same code cannot both succeed.
//
// # Order of checks
//
//   - rec == nil or a typed nil recorder (a nil pointer, map, slice, func or
//     chan wrapped in the interface) returns ErrStepRecorderRequired before
//     anything else. The plain "rec == nil" check is not enough on its own:
//     a typed-nil interface value is non-nil, so without the reflection
//     check a recorder stored as "var rec *myRecorder" would slip past the
//     guard and reach RecordIfNewer, where any method call panics. See
//     isNilRecorderValue.
//   - ctx.Err() != nil returns that error unchanged; the recorder is not
//     called.
//   - VerifyStep is called with lastUsedStep=0, so VerifyStep itself
//     cannot refuse for replay. A refusal here means the code shape is
//     wrong, the secret is wrong, or the code is for the wrong window.
//     The recorder is NOT called in any of those cases; Verify reports
//     the failure to the caller and leaves the stored step untouched.
//   - rec.RecordIfNewer is called with the matched step. When it returns
//     ErrCodeReused (or any error wrapping it), Verify returns an error
//     that satisfies errors.Is(err, ErrCodeReused). Any other error is
//     wrapped with "totp: record step:" so the recorder's signal
//     survives, the caller can still tell reuse from a storage failure,
//     and the wrapped chain points back at the recorder's diagnostic.
//
// # Errors:
//
//	totp.ErrStepRecorderRequired - rec is nil or a typed nil; the recorder was not wired
//	totp.ErrMalformedCode        - not six decimal digits
//	totp.ErrInvalidSecret        - secret is not base32 or not 20 bytes decoded
//	totp.ErrInvalidCode          - six digits, matches no step in the window
//	totp.ErrCodeReused           - the recorder refused to advance the step
//	wrapped storage error        - "totp: record step: ..." for any recorder failure that is not ErrCodeReused
//	context.Canceled / DeadlineExceeded - returned unchanged only when ctx was already cancelled
//	                                 before Verify ran. A recorder that returns context.Canceled is
//	                                 wrapped with "totp: record step:" so errors.Is(err, context.Canceled)
//	                                 still holds but == no longer does.
//
// # Example
//
//	rec := totpPostgresRecorder{db: db, enrollmentID: userID}
//	err := totpMod.Verify(ctx, secret, presented, rec)
//	switch {
//	case errors.Is(err, totp.ErrCodeReused):
//	    // Log it and refuse. A double submission of one code also lands here.
//	    log.Warn("totp: replay attempt (user=%s)", userID)
//	    return http.StatusUnauthorized
//	case err != nil:
//	    return http.StatusUnauthorized
//	}
func (t *TOTP) Verify(ctx context.Context, secret, code string, rec StepRecorder) error {
	if t == nil || !t.initialised {
		return ErrNotInitialised
	}
	if isNilRecorderValue(rec) {
		return ErrStepRecorderRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	step, err := t.VerifyStep(secret, code, 0)
	if err != nil {
		return err
	}
	switch err := rec.RecordIfNewer(ctx, step); {
	case err == nil:
		return nil
	case errors.Is(err, ErrCodeReused):
		return ErrCodeReused
	default:
		return fmt.Errorf("totp: record step: %w", err)
	}
}

// isNilRecorderValue reports whether the dynamic value held by rec is a nil
// pointer, map, slice, func or chan. A plain "rec == nil" cannot see this:
// an interface holding a typed nil is itself non-nil, so a caller that passes
// "var r *myRecorder" would slip past the guard and reach RecordIfNewer,
// where every method call panics. The same shape is used by the root
// package's isNilValue in keystore.go.
func isNilRecorderValue(rec StepRecorder) bool {
	if rec == nil {
		return true
	}
	rv := reflect.ValueOf(rec)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

// HashRecoveryCode returns the keyed HMAC-SHA256 hex digest of code,
// matching the values stored in Enrollment.RecoveryHashes.
//
// It returns ErrNotInitialised on a zero-value TOTP, whose hash would be
// keyed with nothing.
func (t *TOTP) HashRecoveryCode(code string) (string, error) {
	if t == nil || !t.initialised {
		return "", ErrNotInitialised
	}
	return t.hashRecoveryCode(code), nil
}

// VerifyRecoveryCode reports whether code matches any of storedHashes,
// scanning every hash in constant time. Returns the zero-based index of
// the matched hash and true on success. The caller MUST mark that code
// as used (delete or flag the row) before the next call - otherwise the
// same code can be redeemed repeatedly.
//
// Verification normalises code on the way in (hyphens and spaces are
// stripped, letters are uppercased), so users can read codes off a
// printout with any grouping they like.
func (t *TOTP) VerifyRecoveryCode(code string, storedHashes []string) (int, bool) {
	if t == nil || !t.initialised {
		return 0, false
	}
	candidate := t.hashRecoveryCode(normalizeRecoveryCode(code))
	var matchedIdx int
	var matched byte
	for i, h := range storedHashes {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(h)) == 1 {
			matched = 1
			matchedIdx = i
		}
	}
	if matched == 0 {
		return 0, false
	}
	return matchedIdx, true
}

// randomBytes returns n bytes of CSPRNG output.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// hashRecoveryCode returns the keyed HMAC-SHA256 hex digest of the
// normalised form of code (no hyphens, no spaces, uppercase), peppered
// with the library's managed refresh secret. Normalising here means
// Enroll, HashRecoveryCode and VerifyRecoveryCode all hash the same
// byte sequence regardless of how the user typed the code.
func (t *TOTP) hashRecoveryCode(code string) string {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

// maxEncodedSecretLen is the longest base32 input decodeSecret will look at.
// A 20-byte secret encodes to 32 characters unpadded and 32 with padding,
// since 20 bytes is already a whole number of 40-bit base32 groups. The few
// extra characters leave room for nothing in particular and exist so an
// oversized input is refused before it is decoded rather than after.
const maxEncodedSecretLen = 40

// decodeSecret decodes a base32 secret (with or without padding) into raw
// bytes and requires exactly secretLen of them.
//
// The length check is the point. Before it existed the only size test was
// len(key) == 0, so any secret that decoded to at least one byte was accepted
// and used as an HMAC key: "MZXW6YTB" decodes to 5 bytes, and a 40-bit TOTP
// secret is enumerable. Enroll always mints secretLen bytes, so nothing this
// package generates was affected; the exposure is a secret arriving from
// outside, migrated from another implementation, pasted by a user, or
// restored from a store that truncated it.
//
// Short inputs did fail before this, which is what made the gap easy to miss,
// but they failed for the wrong reason. The encoding is chosen by
// len(s)%8 != 0, so a length that is not a multiple of 8 gets the padded
// encoding and is rejected as malformed. That reads like a length control and
// is not one: every length that is a multiple of 8 took the unpadded branch
// and decoded cleanly at any size.
func decodeSecret(s string) ([]byte, error) {
	if s == "" || len(s) > maxEncodedSecretLen {
		return nil, ErrInvalidSecret
	}
	// One encoding is enough now, and that is a consequence of the length
	// check rather than a separate decision. secretLen is 20 bytes, which is
	// exactly four 40-bit base32 groups, so it encodes to 32 characters with
	// no padding and the padded and unpadded forms of a valid secret are
	// byte-identical. The branch that used to switch encodings on
	// len(s)%8 != 0 could therefore no longer produce an accepted result:
	// every input it selected the padded encoding for is one the length check
	// rejects anyway. Measured before removing it.
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := enc.DecodeString(s)
	if err != nil || len(key) != secretLen {
		return nil, ErrInvalidSecret
	}
	// The decoder skips "\r" and "\n", so a secret with line breaks decoded
	// to the same key; accept only the spelling Enroll hands out.
	if enc.EncodeToString(key) != s {
		return nil, ErrInvalidSecret
	}
	return key, nil
}

// stepMatches reports whether code equals the 6-digit TOTP value for
// step under key, comparing in constant time.
func stepMatches(step uint64, key []byte, code string) bool {
	otp := generateTOTP(key, step)
	return subtle.ConstantTimeCompare([]byte(otp), []byte(code)) == 1
}

// generateTOTP returns the 6-digit decimal TOTP value for step under
// key (RFC 4226 HOTP on an 8-byte big-endian counter).
func generateTOTP(key []byte, step uint64) string {
	mac := hmac.New(sha1.New, key) //nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	// RFC 4226 §5.3 dynamic truncation.
	offset := sum[len(sum)-1] & 0x0F
	truncated := (uint32(sum[offset])&0x7F)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := truncated % 1_000_000
	return fmt.Sprintf("%06d", mod)
}

// buildURI assembles the otpauth:// URI for the enrollment.
//
// With Issuer set:
//
//	otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}
//
// Both issuer occurrences are percent-encoded; the colon between them
// stays literal (it is structural). With Issuer empty:
//
//	otpauth://totp/{account}?secret={secret}
//
// The authenticator algorithm, digits and period are also included so
// any client that does parse them sees the closed defaults.
func buildURI(issuer, account, secret string) (string, error) {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("algorithm", algoSHA1)
	q.Set("digits", strconv.Itoa(digits))
	q.Set("period", strconv.Itoa(timeStep))

	// The label is written as text rather than through url.URL: Path is the
	// decoded field, so the escaped label put there was escaped a second
	// time and an issuer "Acme Corp" reached the authenticator as
	// "Acme%20Corp" (measured 2026-09-25). A colon inside the issuer or the
	// account is escaped too, so the one literal colon stays the separator.
	label := escapeLabelPart(account)
	if issuer != "" {
		label = escapeLabelPart(issuer) + ":" + label
		q.Set("issuer", issuer)
	}
	return "otpauth://totp/" + label + "?" + q.Encode(), nil
}

// escapeLabelPart percent-encodes one side of an otpauth label, including
// any colon, which the label reserves as its separator.
func escapeLabelPart(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}

// isSixDigits reports whether s is exactly six ASCII decimal digits.
func isSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// formatRecoveryCode inserts a hyphen at the midpoint of an 8-character
// base32 string. 10 raw bytes encode to 16 base32 chars, so the split
// is 8/8: "ABCD1234EFGH5678" -> "ABCD1234-EFGH5678".
func formatRecoveryCode(encoded string) string {
	if len(encoded) != 16 {
		return encoded
	}
	return encoded[:8] + "-" + encoded[8:]
}

// normalizeRecoveryCode strips hyphens and spaces and uppercases so
// users can read codes off a printout with any grouping.
func normalizeRecoveryCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '-' || c == ' ':
			// drop
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 32)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

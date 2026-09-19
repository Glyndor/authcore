# TOTP (Time-based One-Time Password)

`auth/totp` implements the second factor every authenticator app
already speaks: six-digit rotating codes derived from a shared secret
(RFC 6238, layered on RFC 4226 HOTP). authcore enrolls a user by
minting a high-entropy shared secret, returns an `otpauth://` URI the
user's app scans as a QR code, and verifies the codes the user
subsequently produces - all in constant time, with built-in replay
protection.

The library never stores anything; you store the secret and the
recovery-code hashes. See the [error reference](errors.md).

## Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())
totpMod, err := totp.New(auth)                       // defaults
totpMod, err := totp.New(auth, totp.Config{Issuer: "Acme"})
```

## Enrolling a user

```go
enr, err := totpMod.Enroll("alice@example.com")
if err != nil { return http.StatusInternalServerError }

// Show the URI to the user as a QR code; show RecoveryCodes as a
// printable list, exactly once. The user types RecoveryCodes into the
// app OR the app scans the QR code, which encodes the URI.
qrImageFromURI(enr.URI)
printAndWipe(enr.RecoveryCodes) // 10 codes by default

// Persist the secret (lookup key) and the hashes (verification
// material). Never persist RecoveryCodes; the raw codes must not
// survive the request.
db.StoreTOTP(userID, enr.Secret, enr.RecoveryHashes)
```

The `URI` is an `otpauth://totp/...` URI per the de-facto cross-vendor
standard. It encodes the secret, the issuer (if configured) and the
account name; the algorithm (`SHA1`), digit count (`6`) and time step
(`30` seconds) are also embedded so any client that does parse them
sees the closed defaults. Empty `Config.Issuer` means the URI is built
without the issuer parameter and the label, and the authenticator
displays only the account name.

## Verifying a code

```go
secret     := db.GetSecret(userID)
lastStep   := db.GetLastStep(userID) // 0 if no previous verification
presented  := form.Code              // six digits the user typed

step, err := totpMod.Verify(secret, presented, lastStep)
switch {
case errors.Is(err, totp.ErrCodeReused):
    // A code already accepted was tried again - security event.
    // The user may have given a stolen code to an attacker who is
    // now replaying it from a different network. Log and revoke the
    // factor; do NOT show a different message than a normal failure,
    // or you tell the attacker that the code was once valid.
    log.Warn("totp: replay attempt (user=%s)", userID)
    revokeFactor(userID)
    return http.StatusUnauthorized
case err != nil:
    // ErrInvalidCode (wrong code), ErrMalformedCode (not six digits),
    // ErrInvalidSecret (storage corruption). Same response to the
    // client; the distinction is for logs and rate-limit accounting.
    return http.StatusUnauthorized
}
db.SetLastStep(userID, step) // persist the returned step
```

`Verify` compares the candidate code against every step in the
configured window with `crypto/subtle.ConstantTimeCompare` and never
returns early on the first match, so the time taken does not reveal
which step (if any) matched.

## Recovery codes

Recovery codes are one-time backdoor codes the user can redeem if they
have lost their authenticator device. They are minted at enrollment,
hashed before storage, and must be deleted from the user's record after
successful use.

```go
hashes := db.GetRecoveryHashes(userID)
idx, ok := totpMod.VerifyRecoveryCode(form.RecoveryCode, hashes)
if !ok {
    return http.StatusUnauthorized
}
// Single-use: delete the matched hash so the same code can never
// redeem again.
hashes = append(hashes[:idx], hashes[idx+1:]...)
db.SetRecoveryHashes(userID, hashes)
```

`VerifyRecoveryCode` normalises the input (strips hyphens and spaces,
uppercases letters) and scans every hash in the list in constant time,
returning the index of the match so the caller can mark that one used.
A code not in the list returns `false`. The module does **not**
remember which codes have been redeemed; the caller enforces
single-use by deleting the index that was returned.

## Footguns the caller must handle

Two things the module deliberately does not do, because they belong
to the application and are easy to forget:

1. **Rate limiting is the caller's job.** A six-digit code has a
   million possible values and the window accepts several time steps,
   so unlimited attempts are brute forceable (10 codes/second would
   crack any code in under a day). Throttle failed attempts per user,
   ideally with an exponential backoff after a handful of misses and
   a hard lockout or notification after a dozen.

2. **Recovery codes are single use and the caller enforces it.**
   The module returns the index of the matched code; deleting or
   flagging that row in your store is the caller's responsibility.
   Without that step, a stolen recovery code can be redeemed
   repeatedly until the user notices.

## What is fixed and why

The cryptographic layer is **closed**: HMAC-SHA1, 30-second time
step, 6-digit codes, 20-byte secrets and constant-time comparison
are the interoperability baseline. Every widely-used authenticator
app (Google Authenticator, 1Password, Authy, Microsoft Authenticator,
Bitwarden, ...) ignores the `algorithm`, `digits` and `period`
parameters of an `otpauth://` URI and assumes SHA1/6/30. A
configurable value here produces an enrollment that works in your
test environment and locks the user out on the user's phone. There
is no "strict RFC" escape hatch.

The secret length is enforced on the way in as well as on the way
out. `Verify` refuses any secret that does not decode to exactly 20
bytes with `ErrInvalidSecret`, so a shorter secret carried over from
another implementation is not accepted: enroll that user again.

The policy layer is **open with secure defaults**: see
[configuration](configuration.md) for the principle. The caller can
tune `SkewSteps` (clock-skew window), `RecoveryCodeCount` (how many
recovery codes to mint) and `Issuer` (the label shown in the
authenticator) per deployment without weakening the security floor
the library enforces.

`SkewSteps` is a `*int`, so that leaving it unset ("use the default of
one step either side") stays distinguishable from asking for no
tolerance at all. Use `totp.Int` rather than a temporary local:

```go
cfg := totp.DefaultConfig()
cfg.SkewSteps = totp.Int(0) // only the current step is accepted
mod, err := totp.New(auth, cfg)
```

Getting that distinction wrong is a lockout rather than a weakening: a
plain `int` left at its zero value would give a zero-width window while
the documentation promised one step, and every user whose phone clock
drifts by a few seconds would fail to sign in. `password.Bool` exists
for the same reason on the password policy fields.

## Revoking

Delete the row that stores the secret (or flag it) and check on
lookup. There is no token to expire - a TOTP enrollment lives until
you remove it. To rotate without losing the user's authenticator,
mint a fresh enrollment with `Enroll` and migrate the user's device
to scan the new QR code.

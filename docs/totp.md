# TOTP (Time-based One-Time Password)

`auth/totp` implements the second factor every authenticator app
already speaks: six-digit rotating codes derived from a shared secret
(RFC 6238, layered on RFC 4226 HOTP). authcore enrolls a user by
minting a high-entropy shared secret, returns an `otpauth://` URI the
user's app scans as a QR code, and verifies the codes the user
subsequently produces - all in constant time, with replay protection
that the caller wires through a `StepRecorder`.

The library never stores anything; you store the secret and the
recovery-code hashes, and the `StepRecorder` you implement owns the
last-accepted step. See the [error reference](errors.md).

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

`Verify` compares the candidate code against every step in the
configured window with `crypto/subtle.ConstantTimeCompare` and never
returns early on the first match, so the time taken does not reveal
which step (if any) matched. On success it hands the matched step to
a `StepRecorder` whose `RecordIfNewer` method must compare and advance
the stored step atomically. A nil recorder is a programming error and
is refused with `ErrStepRecorderRequired` before any other check runs.

```go
secret    := db.GetSecret(userID)
presented := form.Code // six digits the user typed
rec       := db.Recorder(userID) // bound to this enrollment

err := totpMod.Verify(ctx, secret, presented, rec)
switch {
case errors.Is(err, totp.ErrCodeReused):
    // A user double-submitting the same code, a stolen code replayed
    // from another network, or a misbehaving client can all produce
    // this. Log it and refuse the attempt. Do NOT revoke the factor
    // on the first occurrence: ErrCodeReused is the normal response
    // to a user who clicked twice, and revoking on it would let any
    // failure (lost network, partial click) lock the user out.
    log.Warn("totp: replay attempt (user=%s)", userID)
    return http.StatusUnauthorized
case err != nil:
    // ErrInvalidCode (wrong code), ErrMalformedCode (not six digits),
    // ErrInvalidSecret (storage corruption), ErrStepRecorderRequired
    // (recorder not wired), or a wrapped recorder failure. Same
    // response to the client; the distinction is for logs and
    // rate-limit accounting.
    return http.StatusUnauthorized
}
```

The recorder must do the compare and the store in one atomic step
across every process that verifies for this enrollment. The model is
a SQL `UPDATE` whose branch is decided by the affected row count.
Reading the step in user code, deciding whether to advance, and
writing later races with itself: two concurrent submissions of the
same code both see the old step, both pass, and the same code is
accepted twice. The recorder is what closes that race.

A reference PostgreSQL recorder (about fifteen lines):

```go
type pgRecorder struct {
    db *sql.DB
    id int64
}

func (r pgRecorder) RecordIfNewer(ctx context.Context, step uint64) error {
    res, err := r.db.ExecContext(ctx,
        `UPDATE totp_enrollments
            SET last_step = $2
          WHERE id = $1 AND active AND last_step < $2`,
        r.id, step)
    if err != nil {
        return err
    }
    n, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if n == 1 {
        return nil
    }
    // Zero rows means the row is missing, revoked, or the stored
    // step is already at or above step. Disambiguate with a follow-up
    // read so the caller sees ErrCodeReused for the second case and a
    // distinct "enrollment missing" error for the first.
    var stored int64
    err = r.db.QueryRowContext(ctx,
        `SELECT last_step FROM totp_enrollments WHERE id = $1 AND active`,
        r.id).Scan(&stored)
    if errors.Is(err, sql.ErrNoRows) {
        return fmt.Errorf("totp: enrollment %d missing or revoked", r.id)
    }
    if err != nil {
        return err
    }
    return totp.ErrCodeReused
}
```

The `UPDATE` is the gate. If two processes race with the same code,
only one of the `UPDATE`s reports a row affected; the other sees zero
rows, runs the follow-up `SELECT`, finds the advanced step, and
returns `ErrCodeReused`. The follow-up `SELECT` exists so the caller
can still tell "code was used" from "enrollment is gone"; without it
the two cases would collapse into one error and the missing-enrollment
diagnosis would disappear in the logs.

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

Three things the module deliberately does not do, because they belong
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

3. **The `StepRecorder` must be atomic.** A recorder that reads the
   step, decides in user code, then writes back races with itself.
   Use a conditional update whose branch is decided by the affected
   row count, or a row-level lock that holds for the duration of the
   compare-and-advance. The recorder's contract is `RecordIfNewer`
   that returns `nil` only after the new step is durable.

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
out. `Verify` and `VerifyStep` refuse any secret that does not decode
to exactly 20 bytes with `ErrInvalidSecret`, so a shorter secret
carried over from another implementation is not accepted: enroll that
user again.

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

## Upgrading from v1.14

`v1.14`'s `Verify(secret, code, lastStep)` is now `VerifyStep`, with
the same signature and the same behaviour. The old implementation was kept
under the name `VerifyStep` as the low-level primitive; it does not read or
write storage, and a caller that passes 0 gets no replay refusal at all.

To get the atomic guarantee, implement a `StepRecorder` over the
column you already store the step in. Initialise the stored step to
0 only when the row is first written (a fresh enrollment); subsequent
verifications advance it. The PostgreSQL example above is the
shortest correct shape: a conditional `UPDATE` whose branch is
decided by the affected row count, followed by a disambiguating
`SELECT` so the caller can still tell `ErrCodeReused` from a missing
or revoked enrollment.

Then call `Verify(ctx, secret, code, rec)` instead of `VerifyStep`.
A nil recorder is refused with `ErrStepRecorderRequired`; a recorder
that returns `ErrCodeReused` propagates it unchanged; any other
recorder error is wrapped with `"totp: record step: "`.

## Revoking

Delete the row that stores the secret (or flag it) and check on
lookup. There is no token to expire - a TOTP enrollment lives until
you remove it. To rotate without losing the user's authenticator,
mint a fresh enrollment with `Enroll` and migrate the user's device
to scan the new QR code.

# Single-use credential tokens

`auth/credential` mints the high-entropy, time-bounded, single-use
tokens that power password reset and account activation - the two most
security-sensitive emails an application ever sends. The module hands
back the raw token once (for the email link) and a keyed hash (for the
caller to store), then verifies a presented token against that stored
hash with the same purpose and subject it was minted for.

The library never stores anything; you own the database. See the
[error reference](errors.md).

## Setup

```go
cfg := authcore.DefaultConfig()
cfg.RequireExistingKeys = true // refuse to run if KeysDir is missing or
                              // empty: a fresh refresh secret would
                              // silently invalidate every stored hash
                              // and every outstanding reset / activation
                              // link in the database.
auth, err := authcore.New(cfg)
cred, err := credential.New(auth)                            // defaults (TTL=1h)
cred, err := credential.New(auth, credential.Config{TTL: 15 * time.Minute})
```

`RequireExistingKeys` is the load-only flag on `authcore.Config` (see
[Key management](key-management.md)). Leaving it at its zero value lets the
library generate a fresh refresh secret on first start, which silently
invalidates every existing credential-token hash and every outstanding
reset or activation link on the next start.

## Password reset flow

```go
// 1. User clicks "I forgot my password". Issue a reset token.
issued, err := cred.Issue("reset", user.Email)
if err != nil { return http.StatusInternalServerError }

// 2. Email the raw token in a link. NEVER store the raw token.
link := "https://app.example.com/reset?token=" + url.QueryEscape(issued.Token)
sendEmail(user.Email, "Reset your password", linkBody(link))

// 3. Persist the hash alongside the issuance timestamp. The hash binds
//    purpose and subject into a single value - a "reset" token can
//    never be redeemed against an "activate" flow, and alice's token
//    can never be redeemed for bob.
db.StoreResetToken(user.ID, issued.Hash, time.Now())

// 4. User clicks the link. Verify and act, in the same transaction
//    that consumes the token.
stored, err := db.FindResetToken(user.ID)
if err != nil { return genericError() }

err = cred.Verify("reset", user.Email,
    form.Token, stored.Hash, stored.IssuedAt)
switch {
case errors.Is(err, credential.ErrExpired),
     errors.Is(err, credential.ErrInvalidCredential):
    // Same generic message either way: distinguishing them tells an
    // attacker that a token existed.
    return http.StatusOK // "link invalid or expired"
case err != nil:
    return http.StatusInternalServerError
}

// Single-use: delete the row by the exact hash, in the same transaction
// that updates the password. The conditional delete is the control that
// makes the token single-use under concurrency: two requests both verify
// the same valid token, both call DELETE, the first affects one row,
// the second affects zero. Require exactly one affected row before
// applying the effect, otherwise a racing second click changes the
// password it never spent a token on.
res, err := db.Exec(
    `DELETE FROM reset_tokens WHERE user_id = $1 AND hash = $2`,
    user.ID, stored.Hash)
if err != nil {
    return http.StatusInternalServerError
}
n, _ := res.RowsAffected()
if n != 1 {
    return http.StatusOK // someone else redeemed first; same generic message
}
db.UpdatePassword(user.ID, newHash)
```

## Account activation flow

The shape is identical; the only change is the `purpose` string.

```go
issued, err := cred.Issue("activate", newUser.Email)
sendEmail(newUser.Email, "Activate your account", linkBody(activationLink(issued.Token)))
db.StoreActivationToken(newUser.ID, issued.Hash, time.Now())

// Later, when the user clicks the activation link:
err = cred.Verify("activate", newUser.Email,
    form.Token, stored.Hash, stored.IssuedAt)
// ... same generic-error handling as the reset flow ...
db.MarkUserActive(newUser.ID) // and delete the activation token
```

A token minted for activation can never be redeemed against reset,
because the purpose is bound into the stored hash and Verify recomputes
it from the caller's arguments.

## What you must do on top

The module does three things well: it makes the token unguessable
(256-bit CSPRNG), it binds the token to its purpose and subject so it
cannot be redeemed against the wrong flow or the wrong user, and it
rejects tokens whose issuedAt is more than one minute in the future
(to catch a clock that has run ahead). Three things the module
deliberately does NOT do, because they belong to the application and
forgetting any one of them ships a broken reset flow:

1. **Single-use is the caller's job.** The module does not remember
   anything; it cannot tell whether a token has been redeemed before.
   Delete or flag the stored hash in the same transaction that applies
   the effect (the `db.DeleteResetToken` line above). Without that
   step, a stolen link can be spent over and over until it expires on
   its own.

2. **Changing the password must invalidate outstanding reset tokens
   for that user.** An old reset link in an old inbox still works
   after the user has recovered their account, which is exactly the
   case reset exists to close. A `DELETE FROM reset_tokens WHERE
   user_id = ?` in the password-change transaction closes it.

3. **Rate limit issuance per subject.** Otherwise the endpoint is a
   mail bomb aimed at any address the attacker names. Throttle per
   email and per IP, and surface a generic "if that address exists,
   we sent a link" message so the existence oracle does not leak.

## Token shape

- 32 random bytes (256 bits) from `crypto/rand`
- base64 URL **without padding**, so the token drops into a query
  parameter as-is and `url.QueryEscape(token) == token`
- The hash is `HMAC-SHA256(pepper, purpose || subject || token)`
  hex-encoded, with each field prefixed by its length as a big-endian
  `uint32`. That is what makes `(purpose="reset", subject="ab")`
  unable to collide with `(purpose="reseta", subject="b")`, and unlike
  a separator byte it holds no matter what the fields contain: a Go
  string can hold a NUL, so `("a\x00b", "c")` and `("a", "b\x00c")`
  would hash alike under a `0x00` separator. The pepper is the
  library's managed refresh secret, never the database row.
- Verify compares the recomputed hash against `storedHash` in constant
  time, runs the comparison before the expiry check, and returns
  `ErrInvalidCredential` or `ErrExpired` - the caller shows the same
  generic message for both.

## Footguns the caller must handle

Beyond the three above, two smaller traps:

- **Store `issuedAt` alongside the hash.** Without it the caller
  cannot pass a meaningful timestamp to Verify, and the module falls
  back to "every link is expired". A two-column row (hash, issued_at)
  is enough.
- **Bind the subject to something stable and unique.** The usage
  example above uses `user.Email`, which is the right choice if email is
  the account identifier. If the caller uses a mutable field (a
  display name, say), a user who renames themselves invalidates
  their own outstanding reset links. Email is the conventional
  choice; a frozen user ID or account number works too.

## What is fixed and why

The cryptographic layer is **closed**: token entropy, the
HMAC-SHA256 construction and its library-managed pepper, the
constant-time comparison, the base64-URL encoding, and the binding of
purpose and subject into the stored hash are not configurable. Weaken
any of these and a stolen email can be spent against the wrong user
or the wrong flow.

The policy layer is **open with secure defaults**: the TTL (how long
a token remains redeemable) is configurable within a 1-nanosecond to
24-hour range, enforced by `validateConfig`. The 24-hour cap is
deliberately tight - a reset link that lives longer than a day is a
standing key to the account sitting in an inbox.

`TTL` is a plain `time.Duration`, not a pointer, because zero is
refused rather than defaulted - `New(auth, credential.Config{})`
fails with `ErrInvalidConfig`. This is the contrast with `totp`'s
`SkewSteps`, where zero is a meaningful "no tolerance" value. See
[configuration](configuration.md) for the principle.

# Secure login recipe

authcore gives you the parts of authentication you only get wrong once — password
hashing, token signing, timing-safe comparison, key management. It does **not**
build the login flow around them. This page is the checklist for that flow: the
things you, the consumer, still own so the result is login "a security auditor
would accept."

Read it once, wire it once. Each section says what authcore does for you and
what you must add.

> [!IMPORTANT]
> authcore is a library, not an identity server. It has no database, no HTTP
> layer, no rate limiter, no session store. Those are yours. The recipe below is
> how to connect them without opening a hole.

## At a glance

| Concern | authcore does | You must do |
|---|---|---|
| Password storage | Argon2id, salt, PHC, constant-time verify | Store the hash; never the plaintext |
| Password strength | length + composition policy | Decide your own extra rules if any |
| Token signing | EdDSA, alg-confusion-proof, `iss`/`aud`/`exp` enforced | Send/store tokens correctly |
| Refresh tokens | issue + hash + timing-safe compare | Persist the hash, rotate, delete on logout |
| Brute force | — | Rate-limit and lock out |
| User enumeration | constant-time hash compare | Equalize responses **and** timing in your handler |
| Transport | — | TLS, secure cookies, CSRF |
| Instant revocation | short access TTL | Denylist by session id if you need it |

## 1. Registration

```go
// Validate the identifier and the password BEFORE hashing.
emailNorm, err := emailMod.ValidateAndNormalize(req.Email)
if err != nil { return badRequest("invalid email") }

if err := pwdMod.ValidatePolicy(req.Password); err != nil {
    return badRequest(errors.Unwrap(err).Error()) // safe, specific reason
}

hash, err := pwdMod.Hash(req.Password)
if err != nil { return serverError() }

// Store the normalized identifier + hash. Never the plaintext.
if err := db.CreateUser(emailNorm, hash); err != nil {
    // Duplicate email? See enumeration (§3) — do not reveal "already registered"
    // on a public endpoint; confirm via email instead.
}
```

authcore: validation, policy, hashing. You: storage, and not leaking whether the
address already exists.

## 2. Login

```go
emailNorm, err := emailMod.ValidateAndNormalize(req.Email)
if err != nil { return unauthorized() } // generic — see §3

user, err := db.FindUserByEmail(emailNorm)
if err != nil {
    // User not found. Do NOT return early with a different message or timing.
    // Verify against a dummy hash so the response time matches the found case.
    _, _ = pwdMod.Verify(req.Password, dummyHash)
    return unauthorized()
}

ok, err := pwdMod.Verify(req.Password, user.PasswordHash)
if err != nil || !ok {
    return unauthorized() // same generic error as "user not found"
}

// Authenticated — issue tokens (§4).
```

`dummyHash` is one precomputed Argon2id hash of any throwaway password, stored as
a constant. Verifying against it on the not-found path makes both paths cost the
same Argon2id work, so an attacker cannot tell "no such user" from "wrong
password" by timing.

authcore: constant-time hash verify. You: identical error **and** identical
timing on every failure (see §3).

## 3. No user enumeration

An attacker must not be able to discover which emails/usernames are registered.
Three leaks to close, all in your handler:

- **Message:** every login failure returns the same generic error
  (`unauthorized`), whether the user is missing or the password is wrong.
- **Timing:** the not-found path must do the same Argon2id work as the found path
  (the `dummyHash` verify in §2). Without it, "no such user" returns in
  microseconds and "wrong password" in ~50 ms — a trivial oracle.
- **Side channels:** registration, password reset, and resend-verification must
  not reveal existence either. Prefer "if that address exists, we sent a link"
  over "no account with that email."

## 4. Sessions & cookies

```go
pair, err := jwtMod.CreateTokens(user.ID, MyClaims{Role: user.Role})
if err != nil { return serverError() }

// Store ONLY the refresh hash, keyed by the session id.
db.StoreSession(pair.SessionID, user.ID, pair.RefreshTokenHash, pair.RefreshTokenExpiresAt)
```

Deliver tokens safely:

- Send the **refresh token** in an `HttpOnly`, `Secure`, `SameSite=Strict` (or
  `Lax`) cookie — never readable by JavaScript.
- Keep the **access token** in memory on the client where possible; if you must
  cookie it, same flags.
- Serve everything over **TLS only**. A bearer token on plaintext HTTP is a
  leaked credential.
- If you authenticate via cookies, add **CSRF** protection (double-submit token
  or `SameSite`).

authcore: token issuance + the hash to store. You: cookie flags, TLS, CSRF.

## 5. Refresh & rotation

Verify the presented refresh token against your stored hash **before** rotating —
this is what detects a stolen, replayed token.

```go
session, err := db.FindSession(/* from cookie */)
if err != nil { return unauthorized() }

if !jwtMod.VerifyRefreshTokenHash(clientToken, session.RefreshTokenHash) {
    return unauthorized() // timing-safe compare
}

newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
if err != nil { return unauthorized() }

// Atomically replace the old hash. If the same old token is presented twice,
// the second attempt finds no matching hash → treat as compromise (optionally
// revoke the whole session family).
db.ReplaceRefreshHash(session.ID, newPair.RefreshTokenHash)
```

authcore: signature + expiry verification, timing-safe hash compare, stable
`SessionID` across rotations. You: the stored-hash lookup, the atomic swap, and
the reuse-detection decision.

## 6. Logout & revocation

```go
db.DeleteSession(session.ID) // stops renewal
```

> [!WARNING]
> Deleting the refresh hash stops the session from being **renewed** — it does
> **not** invalidate the access token the client already holds. A stateless
> access token stays valid until its `exp` (the `AccessTokenTTL`, 15 min by
> default). See [JWT — Revocation & logout](jwt.md#revocation--logout).

- **Most apps:** the short access TTL is enough — the token dies on its own.
- **Need instant kill** (logout-everywhere, account compromise): set a
  `jwt.Denylist` on the config and add the `SessionID` to your store on logout —
  `VerifyAccessToken` then returns `ErrTokenRevoked`. See
  [JWT — Revocation & logout](jwt.md#revocation--logout).

## 7. Brute force & lockout

authcore does no rate limiting. Add it:

- **Throttle** login, refresh, password-reset and registration per IP and per
  account.
- **Lock out** an account after N consecutive failures (exponential backoff or a
  temporary ban), and surface it without revealing whether the account exists.
- Apply the same to **password reset** and **MFA** endpoints.

## 8. What authcore covers here, and what it does not

Three of the things this section used to list as your job have shipped since it
was written. Reach for them rather than hand rolling the flow:

- **MFA / TOTP** is [`auth/totp`](totp.md): codes, drift window, and
  single-use recovery codes.
- **Password reset and email verification** are
  [`auth/credential`](credential.md): single-use tokens, hashed at rest,
  expiring.
- **Encrypting an identifier while keeping it unique** is
  [`auth/field`](field.md): AES-256-GCM plus a blind index a `UNIQUE`
  constraint can run against.

Still yours:

- **Account lockout and rate limiting.** They need state authcore does not
  hold, and the right policy is a property of your product.
- **Breached-password rejection** is intentionally not part of authcore. The
  built-in policy is length + composition only.

## The one-line summary

authcore removes the cryptographic mistakes. This recipe removes the flow
mistakes. Do both and your login is solid; skip §3 or §7 and strong hashing
won't save you.

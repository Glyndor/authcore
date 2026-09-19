# Key management

On first run authcore creates `KeysDir` (default `.authcore`) and generates:

| File | Format | Mode | Purpose |
|---|---|---|---|
| `ed25519_private.pem` | PKCS#8 PEM | `0600` | Signing key |
| `ed25519_public.pem` | PKIX PEM | `0644` | Verification key |
| `refresh_secret.key` | 32-byte hex | `0600` | HMAC-SHA256 key for refresh token hashing, **and** the HKDF root for every `auth/field` column key. See below. |
| `metadata.json` | JSON | `0600` | Records which on-disk layout wrote the directory |
| `.gitignore` | `*` | `0600` | Prevents accidental commits |

On subsequent starts the files are loaded and the key pair is validated for
consistency. If only one PEM file is present, `New()` returns `ErrKeyManager` —
delete both to regenerate.

## The layout marker

`metadata.json` holds no key material — a format version, when the keys were
first written, and the id of the current signing key:

```json
{
  "format": 1,
  "created": "2026-07-27T02:41:09Z",
  "key_id": "3f9a1c07d5b2e846"
}
```

It exists so that a release which changes the on-disk format can **migrate what
is already there** rather than regenerate it. Regenerating would invalidate
every refresh-token and API-key hash you have stored, logging out all of your
users — which authcore treats as a defect, not an acceptable breaking change.

What that means in practice:

- A directory created **before this file existed** carries no marker. It is
  adopted in place on the next start: the marker is written, the keys are not
  touched. Nothing is required of you.
- A directory reporting a **newer** format than the running build understands is
  **refused**, keys untouched. Upgrade authcore rather than downgrading the
  directory.
- A **corrupt** marker is also refused, because a loader that cannot tell what
  wrote the keys must not guess at them. The file holds no secret, so deleting
  it is safe and makes the next start re-adopt the existing keys — the error
  says so.
- If the marker **cannot be written** (a read-only mounted secret, for example)
  authcore logs a warning and carries on. It is bookkeeping; it never blocks
  startup.

The recorded `key_id` follows the keys: rotate them by replacing the PEM files
and the marker is updated on the next start.

## Containers & multiple replicas

The zero-config default persists keys to `.authcore` in the working directory.
That is fine on a host with a durable disk, but a container filesystem is
**ephemeral** and a deployment usually runs **more than one replica**. With the
default, two things break — silently:

> [!WARNING]
> - **On restart / redeploy** the `.authcore` directory is gone, so authcore
>   generates a **new** key pair (it logs a `WARN`). Every access token already
>   issued fails signature verification and every refresh-token hash stored in
>   your database stops matching — **every user is logged out**.
> - **With multiple replicas** each pod generates **its own** key pair, so a
>   token minted by pod A is rejected by pod B (different `kid` and signature).
>   Behind a load balancer, login appears to fail at random.

The fix is to give every instance the **same, stable** keys. Generate them once,
then mount them **read-only** into every replica:

```go
cfg := authcore.DefaultConfig()
cfg.KeysDir = os.Getenv("AUTHCORE_KEYS_DIR") // e.g. /run/secrets/authcore
auth, err := authcore.New(cfg)
```

1. **Pre-generate once** — run authcore in a one-shot job pointed at the volume,
   or generate the three files (`ed25519_private.pem`, `ed25519_public.pem`,
   `refresh_secret.key`) with any Ed25519 tool, and store them as a Kubernetes
   Secret / Docker secret.
2. **Mount the *same* set read-only** into every replica at `KeysDir`. Do **not**
   give each pod a writable empty volume — each would generate its own keys and
   reintroduce the multi-replica break above.
3. Keep the volume durable across restarts so the keys (and therefore live
   sessions) survive a redeploy.

> [!NOTE]
> A read-only `KeysDir` works: when all three files already exist, authcore only
> loads and validates them — it never writes. It writes only when generating a
> missing file on first run, which a pre-generated mount avoids entirely.

## Sourcing keys without a volume (KeyStore)

If mounting a volume is awkward — serverless, or keys that live only in a secret
manager — set `Config.KeyStore` to source the material directly instead of from
disk. `KeysDir` is then ignored.

```go
cfg := authcore.DefaultConfig()

// Keys arrive as PEM strings from env / a secret manager.
ks, err := authcore.NewKeyStoreFromPEM(
    []byte(os.Getenv("AUTHCORE_PRIVATE_PEM")),
    []byte(os.Getenv("AUTHCORE_PUBLIC_PEM")),
    refreshSecretBytes, // raw 32 bytes
)
if err != nil { log.Fatal(err) }
cfg.KeyStore = ks

auth, err := authcore.New(cfg)
```

`NewKeyStoreFromKeys(priv, pub, secret)` takes already-parsed Ed25519 values for
the same purpose. Both validate that the public key matches the private key and
that the refresh secret is 32 bytes, so a misconfigured secret fails loudly at
startup rather than producing tokens no replica can verify. Inject the **same**
material into every replica, exactly as with a shared volume.

To implement a fully custom source (KMS that signs without exposing the private
key would need more than this), satisfy the one-method `KeyStore` interface
yourself: `Load() (authcore.Keys, error)`.

> [!NOTE]
> The disk default stores the private key and refresh secret **unencrypted**
> (owner-only `0600`, like an SSH key). For a high-assurance deployment, source
> the material from a secret manager / KMS via a `KeyStore` instead of leaving it
> in plaintext on disk.

The `KeyID()` accessor returns a 16-character hex digest derived from the public
key. It is embedded in every token's `kid` JOSE header. Verification selects the
key by `kid` and rejects any token whose `kid` is not one the module accepts.

## The refresh secret carries two jobs, and only one of them is recoverable

`refresh_secret.key` is the HMAC-SHA256 key for refresh token hashing. Since
`auth/field` shipped it is also the input `auth/field` runs HKDF-SHA256 over to
derive the AES-256-GCM column key and the blind index key, with a distinct info
label for each.

That is cryptographic separation, not operational separation, and the
difference is the whole of this section. The two jobs fail very differently:

- **Lose it as a token hashing key** and every refresh token stops verifying.
  Users log in again. Annoying, recoverable, over in a day.
- **Lose it as the `auth/field` root** and every encrypted column is
  permanently unreadable. There is no recovery path, because there is no copy
  of the key anywhere else by design.

So back this file up the way you back up the database, not the way you back up
a session store. And if you use `auth/field`, **do not rotate this file in
place.** Rotating it is a table migration: read every row with a module built
on the old secret, write it back with one built on the new secret, in batches,
one transaction per row. The procedure is written out in
[field encryption](field.md#footguns-the-caller-must-handle).

If you do not use `auth/field`, rotating it is exactly as cheap as it sounds:
replace the file, everyone logs in again.

## Rotating the signing key (zero downtime)

Rotating the Ed25519 key without logging everyone out is a two-phase move that
relies on `kid`: tokens already in the wild were signed by the old key, so the
verifier must keep accepting it until they expire.

1. **Overlap.** Make the new key the active one (new `KeysDir` / `KeyStore`
   material) and list the **old public key** in `jwt.Config.PreviousPublicKeys`.
   New tokens are signed only with the new key; tokens still bearing the old
   `kid` keep verifying.

   ```go
   cfg := jwt.DefaultConfig()
   cfg.PreviousPublicKeys = []ed25519.PublicKey{oldPublicKey}
   jwtMod, _ := jwt.New[MyClaims](auth, cfg)
   ```

2. **Retire.** Once every token signed by the old key has expired (at most one
   `RefreshTokenTTL`), deploy again without it. The old key is gone.

Each listed key is indexed by its derived `kid`, so a token picks the right key
automatically. A `kid` that is neither the current key nor a listed previous key
is rejected as `ErrTokenInvalid`.

> [!NOTE]
> Key-file loaders enforce a **4 KiB size cap**. A healthy Ed25519 PEM is ~200
> bytes; anything larger is refused before it reaches `pem.Decode`, protecting
> startup from a corrupted or attacker-replaced key file that would otherwise be
> loaded whole into memory.

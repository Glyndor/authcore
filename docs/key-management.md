# Key management

On first run authcore creates `KeysDir` (default `.authcore`) and generates:

| File | Format | Mode | Purpose |
|---|---|---|---|
| `ed25519_private.pem` | PKCS#8 PEM | `0600` | Signing key |
| `ed25519_public.pem` | PKIX PEM | `0644` | Verification key |
| `refresh_secret.key` | 32-byte hex | `0600` | HMAC-SHA256 key for refresh token hashing |
| `.gitignore` | `*` | `0600` | Prevents accidental commits |

On subsequent starts the files are loaded and the key pair is validated for
consistency. If only one PEM file is present, `New()` returns `ErrKeyManager` —
delete both to regenerate.

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

The `KeyID()` accessor returns a 16-character hex digest derived from the public
key. It is embedded in every token's `kid` JOSE header. Verification selects the
key by `kid` and rejects any token whose `kid` is not one the module accepts.

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

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

A pluggable key source (env / secret manager / KMS instead of files) is on the
roadmap for deployments that prefer not to use a mounted volume.

The `KeyID()` accessor returns a 16-character hex digest derived from the public
key. It is embedded in every token's `kid` JOSE header, enabling zero-downtime
key rotation. Verification rejects tokens whose `kid` does not match the module's
current key id, so a future multi-key deployment only ever accepts tokens minted
under an authorised key.

> [!NOTE]
> Key-file loaders enforce a **4 KiB size cap**. A healthy Ed25519 PEM is ~200
> bytes; anything larger is refused before it reaches `pem.Decode`, protecting
> startup from a corrupted or attacker-replaced key file that would otherwise be
> loaded whole into memory.

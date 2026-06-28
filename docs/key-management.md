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

**In containers or CI**, point `KeysDir` at a mounted secrets volume:

```go
cfg := authcore.DefaultConfig()
cfg.KeysDir = os.Getenv("AUTHCORE_KEYS_DIR") // e.g. /run/secrets/authcore
auth, err := authcore.New(cfg)
```

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

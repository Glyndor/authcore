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
consistency. If only the public PEM is missing with the private key and
refresh secret intact, reconstruct the public half from the private key (the
second 32 bytes of an Ed25519 private key as `crypto/ed25519` produces it, or
the 32 bytes `priv[32:]` returned by `priv.Public()`); do not delete the
private key to "regenerate" it, and do not delete `refresh_secret.key` to
make the directory appear empty. That destroys secrets the rest of the
deployment still depends on.

authcore warns (and never refuses or chmods) when `ed25519_private.pem` or
`refresh_secret.key` is readable by group or others on the load paths. The
Podman default mount without an explicit `mode` is 0444 and the Kubernetes
Secret volume default is 0644, both of which trip this check, so a freshly
mounted secret in a container cluster produces one warning per affected file
at startup until the operator tightens the secret's mode and uid. authcore
does not change the mode itself: a deployment that chose group access on
purpose stays as-is, and a file authcore did not create is not its to rewrite.

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

## Load-only in production

Set `Config.RequireExistingKeys = true` to make the disk store load-only.
`New` reads the three key files from `KeysDir` and never creates, generates,
chmods or writes anything there. The field is the opt-in for production
deployments that provision keys once and mount the result into every replica.

```go
cfg := authcore.DefaultConfig()
cfg.KeysDir = "/run/secrets/authcore" // pre-provisioned by the one-off init
cfg.RequireExistingKeys = true
auth, err := authcore.New(cfg)
```

When the flag is true:

- `New` rejects a missing `KeysDir` and a non-directory entry at that path
  with an error wrapping `ErrInvalidConfig`. The message names the path and
  tells the operator to provision the three files into it (restore them from
  a backup, or generate them once without the flag and mount the result).
- `New` rejects a partial, unreadable or malformed set with the existing
  `ErrKeyManager` envelope. The message names the present and missing files
  and tells the operator to restore the missing ones from a backup; the word
  "delete" never appears.
- The disk store does not run `mkdir`, `chmod`, `gitignore` or `metadata.json`
  writes. A read-only mount loads cleanly, which is the deployment shape the
  recommended compose file uses. See [containers](containers.md).

The one-off key creation runs `authcore-keygen` against a directory that does
not exist yet, then the resulting files are copied into the new volume. The
exact command is the recipe in
[Running authcore in containers](containers.md#recommended-setup); both
sections describe the same step.

The boot sequence that motivated the flag was reproduced on 2026-09-19 with
rootless Podman and podup: a container recreated without a volume started
with brand-new keys and no error, invalidating every issued token, every
stored refresh-token and API-key hash, and every `auth/field` column (whose
key derives from `refresh_secret.key`). A volume that failed to mount or was
mounted at the wrong path is the same situation from the load-only path's
point of view: an empty KeysDir. With the flag set, that situation stops the
service at startup instead.

The flag is ignored when `Config.KeyStore` is set: a custom `KeyStore` already
satisfies "keys are not generated on this machine", so adding load-only on
top would only raise the startup error in places the custom store has
already covered.

## Containers & multiple replicas

The zero-config default persists keys to `.authcore` in the working directory.
That is fine on a host with a durable disk, but a container filesystem is
**ephemeral** and a deployment usually runs **more than one replica**. With the
default, two things break — silently:

> [!WARNING]
> - **On a restart** of the same container the `.authcore` directory is kept,
>   so the keys survive and existing tokens keep verifying.
> - **On a redeploy** that recreates the container without a mounted volume,
>   the `.authcore` directory is gone, so authcore generates a **new** key
>   pair (it logs a `WARN`). Every access token already issued fails
>   signature verification, and every refresh-token hash stored in your
>   database stops matching: **every user is logged out**. A container
>   recreation is not a restart.
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
> A read-only `KeysDir` works: when all three files already exist, authcore
> loads and validates them, and never writes **key material** there. It does
> still try to tighten the directory mode to `0700`, write a `.gitignore`, and
> refresh `metadata.json`. On a read-only mount those writes fail and are
> logged as warnings; startup continues. The PEM files and `refresh_secret.key`
> themselves are only written when a key is missing, which a pre-generated
> mount avoids entirely.

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

### What a custom `Load` must return

`Load` returns either usable material and a nil error, or a non-nil error.
**A miss is an error.** A secret manager lookup that succeeds and finds nothing
must not become `return nil, nil`, and must not become a nil pointer returned as
`Keys`:

```go
func (s vaultStore) Load() (authcore.Keys, error) {
    secret, err := s.client.Read(s.path)
    if err != nil {
        return nil, err
    }
    if secret == nil {
        // Not "return nil, nil": the lookup worked and found nothing.
        return nil, fmt.Errorf("no key material at %s", s.path)
    }
    // ...
}
```

`New` checks what `Load` returned before anything uses it, with the same rules
as `NewKeyStoreFromKeys`:

| Accessor | Must return |
|---|---|
| `PrivateKey()` | 64 bytes: the 32-byte seed followed by the public key that seed derives, which is what `crypto/ed25519` produces. A bare 32-byte seed is refused; expand it with `ed25519.NewKeyFromSeed`. |
| `PublicKey()` | 32 bytes, the public half of `PrivateKey()`. |
| `RefreshSecret()` | Exactly 32 bytes. |

Anything else makes `New` fail with an error that wraps `ErrKeyManager` and
names what was wrong, for example `KeyStore.Load returned nil Keys with a nil
error` or `refresh secret has wrong length: got 16, want 32`. The failure
belongs at startup: before this check, a store that returned `(nil, nil)` passed
`New` and the process panicked on the first token it signed.

The simplest way to satisfy all of it is to fetch the bytes yourself and hand
them to `NewKeyStoreFromKeys` or `NewKeyStoreFromPEM`, and to write a custom
`Keys` only when that does not fit.

> [!NOTE]
> The disk default stores the private key and refresh secret **unencrypted**
> (owner-only `0600`, like an SSH key). For a high-assurance deployment, source
> the material from a secret manager / KMS via a `KeyStore` instead of leaving it
> in plaintext on disk.

The `KeyID()` accessor returns a 16-character hex digest derived from the public
key. It is embedded in every token's `kid` JOSE header. Verification selects the
key by `kid` and rejects any token whose `kid` is not one the module accepts.

## The refresh secret protects credentials and encrypted fields

`refresh_secret.key` is the HMAC-SHA256 key for refresh token hashes
(`auth/jwt`), API-key hashes (`auth/apikey`), TOTP recovery-code hashes
(`auth/totp`) and credential-token hashes (`auth/credential`, including reset
and activation links). It is also the input `auth/field` runs HKDF-SHA256 over
to derive the AES-256-GCM column key and the blind index key, with a distinct
info label for each.

That is cryptographic separation, not operational separation, and the
difference is the whole of this section. The two jobs fail very differently:

- **Lose it as a hashing key** and every stored hash derived from it stops
  verifying. New sessions, API keys, recovery codes and credential links must
  be issued.
- **Lose it as the `auth/field` root** and every encrypted column is
  permanently unreadable. There is no recovery path, because there is no copy
  of the key anywhere else by design.

So back this file up the way you back up the database, not the way you back up
a session store. And if you use `auth/field`, **do not rotate this file in
place.** Rotating it is a table migration: read every row with a module built
on the old secret, write it back with one built on the new secret, in batches,
one transaction per row. The procedure is written out in
[field encryption](field.md#footguns-the-caller-must-handle).

Even without `auth/field`, replacing the refresh secret invalidates every
stored refresh-token hash, API-key hash and TOTP recovery-code hash, plus every
outstanding credential link (reset, activation). Logging in again restores
sessions; it does not restore API keys, recovery codes or credential links.
Arrange to reissue those credentials when replacing the secret.

## Rotating the signing key (zero downtime)

Rotating the Ed25519 key without logging everyone out is a two-phase move that
relies on `kid`: tokens already in the wild were signed by the old key, so the
verifier must keep accepting it until they expire.

1. **Overlap.** Generate a fresh signing pair and list the **old public key**
   in `jwt.Config.PreviousPublicKeys`. New tokens are signed only with the
   new key; tokens still bearing the old `kid` keep verifying.

   When you do this on disk, point the new instance at a fresh `KeysDir`
   *carrying the old `refresh_secret.key` across byte for byte*, either by
   copying it into the new directory before starting, or by sourcing the
   new signing pair through `NewKeyStoreFromKeys` /
   `NewKeyStoreFromPEM` with the existing secret. Initialisation also
   generates a new refresh secret; if that one replaces the old one, every
   stored refresh-token hash, API-key hash, TOTP recovery-code hash and
   outstanding credential link stops matching, and every `auth/field`
   encrypted column becomes unreadable. `New` will not detect this; it
   happens at request time, across the whole deployment. Keep the secret
   stable for the entire rotation, then change it deliberately.

   ```go
   cfg := jwt.DefaultConfig()
   cfg.PreviousPublicKeys = []ed25519.PublicKey{oldPublicKey}
   jwtMod, _ := jwt.New[MyClaims](auth, cfg)
   ```

2. **Retire.** Once every token signed by the old key has expired (at most one
   `RefreshTokenTTL`), deploy again without it. The old key is gone. The
   refresh secret stays.

Each listed key is indexed by its derived `kid`, so a token picks the right key
automatically. A `kid` that is neither the current key nor a listed previous key
is rejected as `ErrTokenInvalid`.

> [!NOTE]
> Key-file loaders enforce a **4 KiB size cap**. A healthy Ed25519 PEM is ~200
> bytes; anything larger is refused before it reaches `pem.Decode`, protecting
> startup from a corrupted or attacker-replaced key file that would otherwise be
> loaded whole into memory.

## What happens if initialisation is interrupted

`New` writes the three key files as a staged publication: the complete set
is generated into a private staging directory `.staging-<random hex>` and
then hard-linked into the final names in the fixed order
`ed25519_private.pem`, `ed25519_public.pem`, `refresh_secret.key`. The
files appear one at a time, in that order; an interruption between links
leaves the directory with whichever subset was already published, and the
next `New` completes the publication from the staging directory rather than
generating a fresh set:

- a crash before the first link leaves an empty directory and a single
  staging directory. The next `New` sees an empty KeysDir and generates a
  fresh set.
- a crash after the private key link, or after the private and public
  links, leaves KeysDir with only the published files and the staging
  directory with the matching bytes. The next `New` recognises the
  partial set, compares every published file byte-for-byte with the staged
  counterpart, links the missing files from the staging directory, and
  loads. The staged publication is recoverable, not orphaned.
- a crash after all three links leaves the directory complete. The next
  `New` loads and reports the leftover staging directory in a Warn log.

Replicas sharing a mounted volume converge on one set: the first process to
hard-link the private key wins; any later initialiser sees the link already
present, drops its own staging directory, waits for the set to be complete,
and loads the winner's keys.

A partial set that cannot be completed (operator deletion with no leftover
staging directory) is refused with advice that names the missing files and
warns that `refresh_secret.key` must not be deleted or regenerated, because
every stored refresh-token hash, API-key hash and every `auth/field`
encrypted column depends on it.

For container deployments (compose files, named volumes, Podman secrets,
SELinux labels, the restart-vs-recreate distinction): see
[Running authcore in containers](containers.md).

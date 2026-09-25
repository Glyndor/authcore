# Running authcore in containers

The library persists an Ed25519 signing key and an HMAC refresh secret under
`Config.KeysDir`, and the format of that directory is its source of truth across
restarts. A container filesystem does not preserve it across recreation, and a
deployment often runs more than one replica. Everything below was measured on
2026-09-19 with rootless Podman 5.7.0 and podup, unless it says otherwise.

## Keys must outlive the container

`KeysDir` left at the default `.authcore` inside the container, no volume
mounted: recreating the container (which any image or config change does, and
`down` then `up` always does) generated a **new** key pair and a **new** refresh
secret. Key id `3c611291ff241d8e` became `b5dae6ac9183fa6a`. A `podman restart`
of the same container kept the key. The new start logs only warnings, no error,
so this fails silently.

The consequences of a new set are wider than lost sessions:

- Every JWT issued by the old key fails signature verification.
- Every stored refresh-token hash and API-key hash stops matching, so users are
  forced to re-authenticate.
- Every `auth/field` column becomes unreadable. The column key is HKDF-derived
  from the refresh secret, and the blind index is HMAC-derived from it, so a
  rotated secret makes ciphertexts and lookup values inert together. Without a
  backup of the old `refresh_secret.key` they cannot be read again.

Recreate != restart. Treat a container recreation the same as a database
deletion: back up the keys first.

## Recommended setup

Generate the keys **once**, back up the directory, then mount it **read-only**
into every replica. This compose file was run with podup, three replicas on one
read-only volume, and all three loaded the same key:

```yaml
services:
  app:
    image: registry.example.com/app:1.0
    user: "1000:1000"
    userns_mode: keep-id
    read_only: true
    restart: unless-stopped
    environment:
      AUTHCORE_KEYS_DIR: /run/authcore
    volumes:
      - authcore_keys:/run/authcore:ro
    deploy:
      replicas: 3

volumes:
  authcore_keys:
    external: true
    name: authcore-production-keys
```

Every line of that file matters:

- `userns_mode: keep-id` maps your host user to the same uid inside the
  container, and `user:` runs the application as that uid. Use your real uid,
  and the same value when the keys are created and when they are read,
  otherwise authcore fails to read `metadata.json` with `permission denied`.
  Plain `keep-id` is enough when the application runs as your own uid. Since
  podup 5.9.4, `keep-id:uid=...,gid=...` is accepted as well; before that it
  failed to start (Glyndor/podup#1798).
- Do not use `userns_mode: auto` for a service that shares a key volume.
  Since podup 5.9.4 it does give each container its own range
  (Glyndor/podup#1797), and that is exactly the problem: a key file written
  as uid 1000 under `keep-id` showed up as owned by `65534` in an `auto`
  container, which then failed with `Permission denied`. `auto` ranges also
  come out of your subordinate uid range (65536 ids by default) and stay held
  while a container exists, stopped ones included. When the range ran out,
  `podup up` failed with `not enough unused IDs in user namespace`. Measured
  on 2026-09-25 with podup 5.10.0 and Podman 5.7.0.
- `read_only: true` makes the container filesystem immutable. The keys volume
  is mounted read-only at `/run/authcore`.
- `AUTHCORE_KEYS_DIR` is just an environment variable. authcore does **not**
  read it; the application reads it and passes the value to `Config.KeysDir`:

  ```go
  cfg := authcore.DefaultConfig()
  cfg.KeysDir = os.Getenv("AUTHCORE_KEYS_DIR")
  cfg.RequireExistingKeys = true // production: refuse to start without a provisioned set
  auth, err := authcore.New(cfg)
  ```

  With `RequireExistingKeys` true, a volume that failed to mount, a volume
  mounted at the wrong path, or an empty read-only bind stops the service at
  startup rather than silently giving every replica new keys and invalidating
  every issued token. The `authcore-keygen` recipe below populates the same
  volume the replicas will later mount read-only.

- `external: true` and `name: authcore-production-keys` point at a named volume
  that already exists. `podup down -v` left it in place when measured; a
  volume that is not declared `external` is removed by `-v`, keys included.

To create the keys **once** into that volume: install `authcore-keygen` on
the host, point it at a directory that does not exist yet, then copy the
resulting files into the volume. `authcore-keygen` is a small tool that exists
precisely for this step: it writes the three key files into a new directory
and never overwrites an existing one, so the application image no longer
needs to perform the one-off generation itself.

```bash
# Install once (Go 1.26+).
go install github.com/Glyndor/authcore/cmd/authcore-keygen@latest

# Generate the set once, into a directory that does not exist yet. It prints
# the path and the key id, never key material. Keep ./keys as your backup:
# losing refresh_secret.key is permanent.
authcore-keygen -out ./keys

# Create the volume and copy the files in from a container that runs with the
# same uid and user namespace as the application, so ownership is right.
# The && is the control: if the volume already exists, podman volume create
# fails and the copy never runs, which is what protects a populated volume
# in production from being overwritten.
podman volume create authcore-production-keys \
  && podman run --rm --user 1000:1000 --userns=keep-id \
       -v ./keys:/src:ro -v authcore-production-keys:/dst \
       docker.io/library/debian:trixie-slim sh -c 'cp -p /src/* /dst/'
```

Creation fails when the volume already exists, and that is deliberate: this
recipe only ever populates a new volume. To replace the keys of a running
deployment, plan a key rotation instead.

On an SELinux-enforcing host, add `,z` to the `/src` bind
(`-v ./keys:/src:ro,z`). The shared label keeps the directory readable to
you and to any later container; without it, the bind mounts but the
container cannot read the files and the error looks like `permission denied`.

Do not use `podman volume import` for this step under rootless Podman: when
measured, a tar made on the host as uid 1000 and imported that way showed up
as uid 999 inside a `keep-id` container running as 1000, and authcore failed
with `permission denied` on `metadata.json`. Copying from a container that
already runs with the application's uid and `--userns=keep-id` keeps the
owner right. Use the application's real uid in both places.

To back up the volume itself later, write the export to a temporary file
and move it into the date-named archive only after the export succeeds. The
shell redirection in `cmd > file` truncates the target before the command
runs, so a one-liner that names the archive by date overwrites an existing
backup from the same day the first time the new export fails partway
through. Exporting to a tempfile and renaming on success keeps the previous
backup in place until the new one is complete:

```bash
tmp=$(mktemp -t keys-backup.XXXXXX.tar)
if podman volume export authcore-production-keys > "$tmp"; then
    mv "$tmp" "keys-backup-$(date +%F).tar"
else
    rc=$?
    rm -f "$tmp"
    exit $rc
fi
```

Concurrent first start is the trap this whole pattern avoids. Eight containers
on one empty named volume, started at once against an unprepared volume, hit
`refusing to write "/keys/ed25519_private.pem": something already exists
there` on 43 of 80 starts in one batch and 51 of 80 in another. The containers
that lost exited with that error; started again, they loaded the winner's keys,
and no two containers ever held different keys. Concurrent first start is being
reworked. Until then, create the keys **once** before starting replicas.

## Replicas

All replicas must read the **same** directory. A per-replica writable volume
("give each pod its own empty volume") makes each replica generate its own
keys, and tokens then verify on some replicas and not others. Behind a load
balancer, login appears to fail at random and never for the same user twice.

The named volume in the recommended setup is read-only and shared, which is
exactly what the constraint requires. With `:ro`, a complete set already
present, and `Config.RequireExistingKeys` set to `true`, authcore reads the
three files and validates them without performing any filesystem writes: no
`MkdirAll`, no directory chmod, no `.gitignore`, no `metadata.json` refresh.
The default disk store (no `RequireExistingKeys`) does attempt those writes,
and on a read-only mount they fail harmlessly and are logged as warnings.

## Podman secrets instead of a volume

If you would rather source the three files from secrets, give each file its own
secret and mount it at the matching name. podup creates the Podman secrets from
the `file:` sources. With the ownership and mode below, each file was mode `400`
and owned by uid 1000 inside the container, and authcore loaded the set:

```yaml
services:
  app:
    image: registry.example.com/app:1.0
    user: "1000:1000"
    userns_mode: keep-id
    read_only: true
    environment:
      AUTHCORE_KEYS_DIR: /run/authcore
    secrets:
      - source: authcore_priv
        target: /run/authcore/ed25519_private.pem
        uid: "1000"
        gid: "1000"
        mode: 0400
      - source: authcore_pub
        target: /run/authcore/ed25519_public.pem
        uid: "1000"
        gid: "1000"
        mode: 0400
      - source: authcore_refresh
        target: /run/authcore/refresh_secret.key
        uid: "1000"
        gid: "1000"
        mode: 0400

secrets:
  authcore_priv:
    file: ./keys/ed25519_private.pem
  authcore_pub:
    file: ./keys/ed25519_public.pem
  authcore_refresh:
    file: ./keys/refresh_secret.key
```

The default secret mount is a regular file with mode `0444` owned by root. That
mode is too loose for a private key, and a uid 1000 process cannot replace it
on a `read_only: true` container. **Set `mode: 0400` and the application's
`uid`/`gid`.** A secret is mounted into the container when it is created.
Since podup 5.9.4, changing a secret's file makes the next `podup up -d`
recreate every container that mounts it (Glyndor/podup#1799): with podup
5.10.0, three replicas were recreated and all three read the new contents.
Older versions left the running containers on the old contents, so there,
recreate every replica explicitly and together.

Either way, check that every replica is running before you rely on the new
keys. When another service in the same `podup up` failed to start, the run
stopped partway: two replicas had loaded the new secret and the third was left
in `Stopping`, serving nothing.

### Using `Config.KeyStore` instead

If mounting any kind of file is awkward, set `Config.KeyStore` and source the
material directly:

```go
// refresh_secret.key holds 64 hex characters; the KeyStore wants the 32 bytes.
secret, err := hex.DecodeString(strings.TrimSpace(os.Getenv("AUTHCORE_REFRESH_SECRET_HEX")))
if err != nil {
    log.Fatal(err)
}
ks, err := authcore.NewKeyStoreFromPEM(
    []byte(os.Getenv("AUTHCORE_PRIVATE_PEM")),
    []byte(os.Getenv("AUTHCORE_PUBLIC_PEM")),
    secret,
)
if err != nil {
    log.Fatal(err)
}

cfg := authcore.DefaultConfig()
cfg.KeyStore = ks
auth, err := authcore.New(cfg)
```

The exact contract the code enforces: `NewKeyStoreFromPEM` and
`NewKeyStoreFromKeys` both call `ValidateMaterial`, which checks
`refresh secret has wrong length: got N, want 32`. The unit is bytes, not hex
characters. The on-disk `refresh_secret.key` holds 64 hex characters
(32 bytes hex-encoded) because the loader hex-decodes the file before storing
the bytes in memory. `NewKeyStoreFromPEM` does not hex-decode; it validates the
input directly, which is why the example decodes it first. Passing the 64 hex
characters unchanged makes startup fail with the length error above, before any
token is signed.

## Changing user, userns, or the host

Ownership does **not** follow the keys when the user mapping, the userns mode,
or the host uid changes. Keys created as uid 1000 inside the container, then
the container run as uid 1001, produced this on startup:

```
read "/keys/metadata.json": open /keys/metadata.json: permission denied
```

Run the application with the uid that created the keys: the same `user:` and
the same `userns_mode` at creation and at runtime. If the uid has to change,
change the ownership of the files deliberately, under the same user namespace
the service will run in, and check that the service starts before removing
anything. Do not delete the files to make the error go away: authcore would
generate new keys, which is the failure this page is about.

## SELinux

For Podman on a SELinux-enabled host:

- Use `:z` when the mounted directory is shared by several containers (a
  read-only keys volume mounted into every replica is the common case). The
  shared label lets all replicas read the same files.
- Use `:Z` when the directory is private to one container. The private label
  blocks every other container on the host, which is what you want for a
  writable per-container mount.

Without a suitable label on an enforcing host, the files are mounted but reading
them is denied, and the error looks like the `permission denied` above even
though the mode and owner are correct. This section follows the Podman
documentation; it was not measured here, since the test host had SELinux off.

## What never to do

- **`podup down -v` on a volume holding keys, when the volume is not declared
  `external`.** `-v` removes ordinary named volumes on the way
  down. The compose file in this page declares the volume `external` precisely
  so `-v` cannot reach it. Without that declaration, the next `up` recreates
  the container against an empty volume, authcore regenerates the keys, and
  every issued token fails verification.
- **Deleting `refresh_secret.key` from a populated directory.** authcore
  treats the three files as a unit. Removing one puts the directory into an
  inconsistent state and `New` returns an error rather than regenerating only
  the missing file; that is on purpose, because a regenerated refresh secret
  invalidates every stored hash. Restore the file from backup, do not delete
  it.
- **Mounting a new empty volume to "fix" a start error.** The start error
  here was always something else (wrong uid, read-only mount of an unrelated
  path, missing secret). A fresh empty volume makes authcore generate new
  keys, which turns a recoverable start error into a permanent token loss.

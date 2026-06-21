# authcore — basic initialisation example

Two ways to construct the library:

1. **Zero config** — call `authcore.New(authcore.DefaultConfig())`. Keys are generated under `./.authcore/` on first run.
2. **Custom config** — override `Timezone`, `EnableLogs`, `KeysDir`, or plug in your own `Logger`.

## Run

```bash
go run ./examples/basic
```

## What it does

- Constructs one `*authcore.AuthCore` with `DefaultConfig()`.
- Constructs a second one with a custom timezone, a silent logger, and a temporary `KeysDir`.
- Prints the resolved configuration + the first 16 hex characters of the public key fingerprint.

## Expected output (abridged)

```
[WARN]  authcore/keymanager: Ed25519 key pair not found, generating new keys in /tmp/authcore-example-XXXXXXXXX
[WARN]  authcore/keymanager: refresh secret not found, generating new secret in /tmp/authcore-example-XXXXXXXXX
[INFO]  authcore initialised (timezone=UTC, logs=true, keys=/tmp/authcore-example-XXXXXXXXX)
timezone      : UTC
logs enabled  : true
keys dir      : /tmp/authcore-example-XXXXXXXXX
public key    : cd1fe09d32c6024e…

timezone      : America/Bogota
logs enabled  : false
```

The temporary `KeysDir` is removed at the end of each run — real apps should point it at persistent storage.

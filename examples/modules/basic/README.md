# authcore: basic initialisation example

Two ways to construct the library:

1. **Zero config**: call `authcore.New(authcore.DefaultConfig())`. Keys are generated under `./.authcore/` on first run.
2. **Custom config**: override `Timezone`, `EnableLogs`, `KeysDir`, or plug in your own `Logger`.

## Run

```bash
cd examples/modules/basic
go run .
```

## What it does

- Constructs one `*authcore.AuthCore` with logs enabled, UTC, and a temporary `KeysDir`. Prints the resolved configuration + the first 16 hex characters of the public key.
- Constructs a second one with a custom timezone, logs disabled, and a temporary `KeysDir`.
- Constructs a third one from `DefaultConfig()` with a custom `Logger` and a temporary `KeysDir`. Its log lines go through that logger.

## Expected output (abridged)

```
[WARN]  authcore: 2026/XX/XX XX:XX:XX authcore/keymanager: KeysDir "/tmp/authcore-example-XXXXXXXXXX" is empty; generating a fresh key set, which invalidates every issued token, every stored refresh-token and API-key hash, and every auth/field encrypted column
[INFO]  authcore: 2026/XX/XX XX:XX:XX authcore/keymanager: recorded on-disk format 1 for /tmp/authcore-example-XXXXXXXXXX
[INFO]  authcore: 2026/XX/XX XX:XX:XX authcore initialised (timezone=UTC, logs=true, keys=/tmp/authcore-example-XXXXXXXXXX)
timezone      : UTC
logs enabled  : true
keys dir      : /tmp/authcore-example-XXXXXXXXXX
public key    : 2d43d80031de9f86…

timezone      : America/Bogota
logs enabled  : false
[WARN]  authcore/keymanager: KeysDir "/tmp/authcore-example-XXXXXXXXXX" is empty; generating a fresh key set, which invalidates every issued token, every stored refresh-token and API-key hash, and every auth/field encrypted column
[INFO]  authcore/keymanager: recorded on-disk format 1 for /tmp/authcore-example-XXXXXXXXXX
[INFO]  authcore initialised (timezone=UTC, logs=true, keys=/tmp/authcore-example-XXXXXXXXXX)
```

The temporary `KeysDir` is removed at the end of each run. Real apps should point it at persistent storage.

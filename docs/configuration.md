# Configuration & logging

## Config

```go
type Config struct {
    EnableLogs bool             // emit log output; default true via DefaultConfig()
    Timezone   *time.Location   // time zone for all operations; default time.UTC
    Logger     authcore.Logger  // custom logger (slog, zap, zerolog, …); overrides EnableLogs
    KeysDir    string           // key storage directory; default ".authcore"
}
```

Always start from `DefaultConfig()` and override only what you need:

```go
cfg := authcore.DefaultConfig()
cfg.EnableLogs = false                    // silence output in tests
cfg.Logger     = slog.Default()           // use your application logger
cfg.KeysDir    = "/run/secrets/authcore"  // absolute path in containers
```

> **Note on `EnableLogs`:** Go cannot distinguish `EnableLogs = false` from a
> zero-value `Config{}`. Start from `DefaultConfig()` to get `EnableLogs = true`,
> then set it to `false` to explicitly opt out.

## Custom logger

Implement the `Logger` interface to route authcore output through your existing
log pipeline:

```go
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
}
```

`*slog.Logger` satisfies this interface directly:

```go
cfg := authcore.DefaultConfig()
cfg.Logger = slog.Default() // or slog.New(yourHandler)
```

When `Config.Logger` is non-nil it takes precedence over `EnableLogs`.

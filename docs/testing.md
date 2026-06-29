# Testing, modules & layout

## Testing your auth layer

Every authcore module accepts a `Provider` interface — not a concrete
`*AuthCore` — which means **you never need to generate real keys or touch the
disk in tests**. Pass in a stub.

```go
package mypkg_test

import (
    "crypto/ed25519"
    "testing"

    "github.com/Glyndor/authcore"
    "github.com/Glyndor/authcore/auth/jwt"
)

// stubProvider implements authcore.Provider with fixed, in-memory dependencies.
type stubProvider struct {
    cfg    authcore.Config
    logger authcore.Logger
    keys   authcore.Keys
}

func (s *stubProvider) Config() authcore.Config { return s.cfg }
func (s *stubProvider) Logger() authcore.Logger { return s.logger }
func (s *stubProvider) Keys() authcore.Keys     { return s.keys }

// stubKeys satisfies authcore.Keys with values you control in the test.
type stubKeys struct {
    priv   ed25519.PrivateKey
    pub    ed25519.PublicKey
    secret []byte
    kid    string
}

func (k *stubKeys) PrivateKey() ed25519.PrivateKey { return k.priv }
func (k *stubKeys) PublicKey() ed25519.PublicKey   { return k.pub }
func (k *stubKeys) RefreshSecret() []byte          { return k.secret }
func (k *stubKeys) KeyID() string                  { return k.kid }

func TestMyHandler(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(nil)
    p := &stubProvider{
        cfg:    authcore.DefaultConfig(),
        logger: &noopLogger{},
        keys:   &stubKeys{priv: priv, pub: pub, secret: []byte("test-secret-32-bytes-long-xxxxxx"), kid: "test"},
    }

    jwtMod, err := jwt.New[struct{}](p, jwt.DefaultConfig())
    if err != nil {
        t.Fatal(err)
    }
    // ... exercise your handler against jwtMod, with no file I/O.
}
```

> [!TIP]
> For deterministic time in tests (e.g. to assert `ExpiresAt`), override
> `Config.Timezone` and use `time.Now()` equivalents through the same clock your
> production code reads from.

## Writing a module

Modules depend on `authcore.Provider` — not the concrete `*AuthCore` — so they
remain independently testable without touching the filesystem or generating real
keys.

```go
// Provider is the narrow interface that *AuthCore satisfies.
type Provider interface {
    Config() Config  // shared configuration
    Logger() Logger  // shared logger sink
    Keys()   Keys    // Ed25519 keys + HMAC secret
}

// Module is the marker interface every sub-module must implement.
type Module interface {
    Name() string // stable, lowercase identifier e.g. "jwt"
}
```

Minimal module skeleton:

```go
package mypkg

import "github.com/Glyndor/authcore"

type MyModule struct {
    log authcore.Logger
    // ...
}

func New(p authcore.Provider, cfg Config) (*MyModule, error) {
    return &MyModule{log: p.Logger()}, nil
}

func (m *MyModule) Name() string { return "mypkg" }
```

In tests, inject a stub `Provider` that returns fixed keys — no disk I/O
required.

## Project layout

```
authcore/
├── authcore.go          # New() · AuthCore struct · compile-time interface assertions
├── config.go            # Config · DefaultConfig()
├── logger.go            # Logger interface · stdlib and noop implementations
├── module.go            # Keys · Provider · Module interfaces
├── errors.go            # Sentinel errors
│
├── internal/
│   ├── clock/           # Timezone-aware Clock — injected for deterministic tests
│   └── keymanager/      # Ed25519 + HMAC key generation, persistence, validation
│
├── auth/
│   ├── jwt/             # JSON Web Token authentication (EdDSA / Ed25519)
│   ├── password/        # Argon2id password hashing
│   ├── email/           # Email validation, normalization, DNS MX verification
│   ├── username/        # Username validation, normalization, reserved name blocklist
│   ├── apikey/          # Opaque API keys (HMAC-SHA256 keyed hash)
│   └── oauth/           # OpenID Connect / OAuth2 client (social login)
│
└── examples/
    ├── basic/           # authcore initialisation strategies
    ├── jwt/             # JWT: create, verify, rotate
    ├── password/        # Password: policy, hash, verify
    ├── email/           # Email: validate, normalize, DNS MX verification
    ├── username/        # Username: validate, normalize, reserved names
    ├── apikey/          # API keys: generate, verify, parse
    ├── oauth/           # Social login: OIDC + OAuth2 flow (separate module)
    ├── fiber/           # Full auth API with Fiber v3 (separate module)
    └── gin/             # Full auth API with Gin (separate module)
```

| Import path | Visibility | Purpose |
|---|---|---|
| `github.com/Glyndor/authcore` | public | Core types and entry point |
| `…/auth/jwt` | public | JWT module |
| `…/auth/password` | public | Argon2id password hashing module |
| `…/auth/email` | public | Email validation, normalization, MX verification |
| `…/auth/username` | public | Username validation, normalization, reserved names |
| `…/auth/apikey` | public | Opaque API key generation and verification |
| `…/auth/oauth` | public | OpenID Connect / OAuth2 client |
| `…/internal/clock` | internal | Shared time abstraction |
| `…/internal/keymanager` | internal | Key generation and persistence |

package oauth

import (
	"fmt"
	"net/http"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
	"github.com/Glyndor/authcore/internal/nilvalue"
)

// Compile-time assertion: *Client must satisfy authcore.Module.
var _ authcore.Module = (*Client)(nil)

// Client is the OIDC client module. Construct one per provider at startup with
// New and share it; it is safe for concurrent use.
//
// A nil or zero-value Client, which New never built, refuses AuthCodeURL,
// Exchange and UserInfo with an error wrapping ErrInvalidConfig and
// VerifyIDToken with an error wrapping ErrIDTokenInvalid.
type Client struct {
	cfg  Config
	log  authcore.Logger
	http *http.Client
	jwks *jwks.Cache
}

// New creates an OIDC Client for a single provider.
//
// New returns a wrapped ErrInvalidConfig when the provider is unusable (a nil
// interface or a Logger() that returns nil) or when cfg is invalid.
func New(p authcore.Provider, cfg Config) (*Client, error) {
	if nilvalue.IsNil(p) {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	if p.Logger() == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	cfg = applyDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c := &Client{
		cfg:  cfg,
		log:  p.Logger(),
		http: cfg.HTTPClient,
		jwks: jwks.New(cfg.Provider.JWKSURL, cfg.HTTPClient, jwks.Errors{Fetch: ErrJWKS, Stale: ErrJWKSStale}),
	}
	c.log.Info("oauth: module initialised (issuer=%s)", cfg.Provider.Issuer)
	return c, nil
}

// errNotBuilt is what a nil or zero-value Client answers: it has no client id
// and no provider, so it must not produce a request or accept a token.
var errNotBuilt = fmt.Errorf("%w: client not initialised, use oauth.New", ErrInvalidConfig)

// built reports whether New produced c. New always creates the key cache.
func (c *Client) built() bool { return c != nil && c.jwks != nil }

// Name returns the module's unique identifier. It implements authcore.Module.
func (c *Client) Name() string { return "oauth" }

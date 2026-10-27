package oauth

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/Glyndor/authcore/internal/redactfmt"
)

// redactedSecret stands in for the client secret, or for the function that
// returns it, wherever a Config or a Client is rendered.
const redactedSecret = "[redacted]"

// Compile-time proof that Config and Client control their own formatting,
// held by pointer or by value.
var (
	_ fmt.Formatter  = Config{}
	_ fmt.Formatter  = (*Config)(nil)
	_ fmt.Stringer   = Config{}
	_ fmt.GoStringer = Config{}
	_ slog.LogValuer = (*Config)(nil)
	_ fmt.Formatter  = Client{}
	_ fmt.Formatter  = (*Client)(nil)
	_ fmt.Stringer   = (*Client)(nil)
	_ fmt.GoStringer = (*Client)(nil)
	_ slog.LogValuer = (*Client)(nil)
)

// describe lists what helps when debugging a login flow and leaves out the
// secrets and the HTTP client.
func (c Config) describe(prefix string) string {
	secret, secretFunc := `""`, `""`
	if c.ClientSecret != "" {
		secret = fmt.Sprintf("%q", redactedSecret)
	}
	if c.ClientSecretFunc != nil {
		secretFunc = fmt.Sprintf("%q", redactedSecret)
	}
	p := c.Provider
	return fmt.Sprintf("%s{ClientID:%q, ClientSecret:%s, ClientSecretFunc:%s, RedirectURL:%q, "+
		"Issuer:%q, AuthURL:%q, TokenURL:%q, JWKSURL:%q, UserInfoURL:%q, Scopes:[%s]}",
		prefix, c.ClientID, secret, secretFunc, c.RedirectURL,
		p.Issuer, p.AuthURL, p.TokenURL, p.JWKSURL, p.UserInfoURL, quoteAll(c.Scopes))
}

func quoteAll(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, " ")
}

// Format renders the config without its client secret. The value receiver
// covers a copy of the config as well as a pointer to it.
func (c Config) Format(f fmt.State, verb rune) {
	redactfmt.FormatWith(f, verb, "oauth.Config", c.String(), c.GoString())
}

// String describes the config without its client secret.
func (c Config) String() string { return c.describe("oauth.Config") }

// GoString is the %#v form of String.
func (c Config) GoString() string { return c.describe("oauth.Config") }

// LogValue keeps slog from reflecting over the config.
func (c *Config) LogValue() slog.Value {
	if c == nil {
		return slog.StringValue("<nil>")
	}
	return slog.StringValue(c.String())
}

// Format renders the client without its client secret.
func (c Client) Format(f fmt.State, verb rune) {
	redactfmt.FormatWith(f, verb, "oauth.Client", c.String(), c.GoString())
}

// String describes the client by its config, without the client secret.
func (c *Client) String() string {
	if c == nil {
		return "<nil>"
	}
	return c.cfg.describe("oauth.Client")
}

// GoString is the %#v form of String.
func (c *Client) GoString() string {
	if c == nil {
		return "(*oauth.Client)(nil)"
	}
	return c.cfg.describe("&oauth.Client")
}

// LogValue keeps slog from reflecting over the client.
func (c *Client) LogValue() slog.Value { return slog.StringValue(c.String()) }

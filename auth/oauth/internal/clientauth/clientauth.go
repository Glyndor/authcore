// Package clientauth chooses how the client authenticates at the token endpoint from the methods the
// provider advertises, and builds the form body for the post method.
package clientauth

import "strings"

// Method is the way Exchange authenticates the client at the token
// endpoint. RFC 6749 section 2.3.1 names Basic as the method a provider must
// support, and OIDC discovery makes token_endpoint_auth_methods_supported
// optional, so a provider that publishes no list tells us nothing and keeps
// the method this library has always sent.
type Method int

const (
	// None means "do not send client credentials": either the
	// caller is a public client without a secret, or the provider advertised
	// only methods this library does not implement. The caller is meant to
	// distinguish them: the former proceeds, the latter errors.
	None Method = iota
	// Basic sends the secret in the HTTP Basic Authorization header.
	Basic
	// Post sends the secret in the form body.
	Post
)

// Choose picks the method Exchange should use, given what the
// provider advertised and whether a secret is configured.
//
// A provider that advertises a list gets what it advertises, preferring Basic
// when it accepts both, since Basic is the OIDC default. A provider that
// advertises nothing gets Post, which is what this library sent before it
// could choose: changing that silently would break every hand-configured
// provider that only accepts Post and publishes no discovery document.
//
// A public client without a secret skips client authentication regardless of
// what the provider advertised, since there is no secret to send; the
// "advertised unsupported method" branch is reserved for a confidential
// client whose provider lists only methods outside this library's pair.
func Choose(advertised []string, hasSecret bool) Method {
	if !hasSecret {
		return None
	}
	if len(advertised) == 0 {
		return Post
	}
	basic := false
	post := false
	for _, m := range advertised {
		switch strings.ToLower(m) {
		case "client_secret_basic", "basic":
			basic = true
		case "client_secret_post", "post":
			post = true
		}
	}
	switch {
	case basic:
		return Basic
	case post:
		return Post
	default:
		return None
	}
}

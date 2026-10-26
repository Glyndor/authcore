// Package hostiletest holds the fixtures shared by the hostile suites of
// auth/oauth: a scripted identity provider, JWKS servers, hand-built JWS
// tokens and the clients that talk to them. The suites attack the OIDC/OAuth2
// client through its public API only; every server here is a local httptest
// server, nothing leaves the machine, and every attack is deterministic.
//
// Only test files import this package.
package hostiletest

// Package claims defines the claim sets carried by access and refresh tokens
// and the limits and type markers that describe them.
package claims

import (
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// TypeAccess and TypeRefresh are the values of the private "type"
// claim used to distinguish the two token kinds at verification time.
const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
)

// MaxTokenLen caps the length of a token string before it is parsed. A genuine
// access/refresh token is a few hundred bytes; refusing anything over 8 KiB
// stops an attacker from forcing base64+JSON work on a multi-megabyte string
// before the signature is even checked.
const MaxTokenLen = 8 * 1024

// Access is the internal claim set for access tokens.
// T carries the application-specific fields stored under the "extra" key.
type Access[T any] struct {
	gjwt.RegisteredClaims
	Type  string `json:"type"`
	Extra T      `json:"extra,omitempty"`
}

// Refresh is the minimal internal claim set for refresh tokens.
// Refresh tokens carry no application-specific data (no extra field) but do
// carry a random RID ("rid") so two tokens of one session never compare equal,
// even when issued in the same wall-clock second. RID is omitted when empty,
// which keeps refresh tokens issued before this field existed parseable.
type Refresh struct {
	gjwt.RegisteredClaims
	Type string `json:"type"`
	RID  string `json:"rid,omitempty"`
}

// NewAccess builds the claim set for an access token.
func NewAccess[T any](issuer, subject, jti string, audience []string, extra T, now time.Time, ttl time.Duration) *Access[T] {
	return &Access[T]{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ID:        jti,
			Audience:  gjwt.ClaimStrings(audience),
			IssuedAt:  gjwt.NewNumericDate(now),
			ExpiresAt: gjwt.NewNumericDate(now.Add(ttl)),
		},
		Type:  TypeAccess,
		Extra: extra,
	}
}

// NewRefresh builds the claim set for a refresh token.
// rid is the per-token random value generated next to signing; pass an empty
// string when reproducing a legacy token that has no rid (verification does
// not require or interpret rid).
func NewRefresh(issuer, subject, jti, rid string, audience []string, now time.Time, ttl time.Duration) *Refresh {
	return &Refresh{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ID:        jti,
			Audience:  gjwt.ClaimStrings(audience),
			IssuedAt:  gjwt.NewNumericDate(now),
			ExpiresAt: gjwt.NewNumericDate(now.Add(ttl)),
		},
		Type: TypeRefresh,
		RID:  rid,
	}
}

// Package jwterr holds the sentinel errors the jwt sub-packages return and the
// jwt package re-exports under the same names, so errors.Is matches whichever
// side of the package boundary produced the error.
package jwterr

import "errors"

var (
	// ErrTokenExpired is re-exported by the jwt package under the same name.
	ErrTokenExpired = errors.New("jwt: token has expired")

	// ErrTokenInvalid is re-exported by the jwt package under the same name.
	ErrTokenInvalid = errors.New("jwt: token is invalid")

	// ErrTokenMalformed is re-exported by the jwt package under the same name.
	ErrTokenMalformed = errors.New("jwt: token is malformed")

	// ErrTokenOversized is re-exported by the jwt package under the same name.
	ErrTokenOversized = errors.New("jwt: token exceeds maximum size")

	// ErrWrongTokenType is re-exported by the jwt package under the same name.
	ErrWrongTokenType = errors.New("jwt: wrong token type")

	// ErrInvalidSubject is re-exported by the jwt package under the same name.
	ErrInvalidSubject = errors.New("jwt: subject must be a valid UUID v7")

	// ErrTokenRevoked is re-exported by the jwt package under the same name.
	ErrTokenRevoked = errors.New("jwt: token has been revoked")
)

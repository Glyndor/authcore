package parse

import (
	"errors"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

// A failure outside the golang-jwt sentinels still surfaces as ErrTokenInvalid
// and keeps its cause beneath it; it never reads as expired or malformed.
func TestMapJWTError_unclassifiedFailureStaysInvalid(t *testing.T) {
	cause := errors.New("something the parser did not classify")

	got := mapJWTError(cause)
	if !errors.Is(got, jwterr.ErrTokenInvalid) || !errors.Is(got, cause) {
		t.Fatalf("mapJWTError(unclassified) = %v, want ErrTokenInvalid wrapping the cause", got)
	}
	if errors.Is(got, jwterr.ErrTokenExpired) || errors.Is(got, jwterr.ErrTokenMalformed) {
		t.Fatalf("mapJWTError(unclassified) = %v, must not read as expired or malformed", got)
	}
}

// Expiry alone maps to ErrTokenExpired; a malformed token to ErrTokenMalformed.
func TestMapJWTError_mapsExpiryAndMalformed(t *testing.T) {
	if got := mapJWTError(gjwt.ErrTokenExpired); got != jwterr.ErrTokenExpired {
		t.Errorf("mapJWTError(expired) = %v, want ErrTokenExpired", got)
	}
	if got := mapJWTError(gjwt.ErrTokenMalformed); got != jwterr.ErrTokenMalformed {
		t.Errorf("mapJWTError(malformed) = %v, want ErrTokenMalformed", got)
	}
}

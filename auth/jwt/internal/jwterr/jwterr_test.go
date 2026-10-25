package jwterr_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

// The messages are part of what callers log and alert on, and each sentinel
// must stay distinct from the others so errors.Is separates them.
func TestSentinels_messagesAndIdentity(t *testing.T) {
	want := map[error]string{
		jwterr.ErrTokenExpired:   "jwt: token has expired",
		jwterr.ErrTokenInvalid:   "jwt: token is invalid",
		jwterr.ErrTokenMalformed: "jwt: token is malformed",
		jwterr.ErrTokenOversized: "jwt: token exceeds maximum size",
		jwterr.ErrWrongTokenType: "jwt: wrong token type",
		jwterr.ErrInvalidSubject: "jwt: subject must be a valid UUID v7",
		jwterr.ErrTokenRevoked:   "jwt: token has been revoked",
	}
	for err, msg := range want {
		if err.Error() != msg {
			t.Errorf("sentinel message = %q, want %q", err.Error(), msg)
		}
		for other := range want {
			if other != err && errors.Is(err, other) {
				t.Errorf("%q must not match %q", err, other)
			}
		}
	}
}

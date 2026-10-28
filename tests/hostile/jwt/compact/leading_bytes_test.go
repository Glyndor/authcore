package compact

import (
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// The base64url decoder skips line breaks, so a token with one in front of the
// header decodes to the very same bytes. It is still a second spelling of the
// token, and is refused on both token kinds, as is any other byte outside the
// alphabet at the very first position.
func TestHostile_CompactForm_firstByteOutsideTheAlphabetIsRefused(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	pair, err := m.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"\n", "\r", "\r\n", "\t", "\x00", "=", "+", "/"} {
		if c, err := m.VerifyAccessToken(prefix + pair.AccessToken); c != nil || !hostiletest.IsInvalidOrMalformed(err) {
			t.Errorf("access token behind %q = %+v, %v; want ErrTokenInvalid or ErrTokenMalformed", prefix, c, err)
		}
		if p, err := m.RotateTokens(prefix+pair.RefreshToken, hostiletest.Extra{}); p != nil || !hostiletest.IsInvalidOrMalformed(err) {
			t.Errorf("refresh token behind %q = %+v, %v; want ErrTokenInvalid or ErrTokenMalformed", prefix, p, err)
		}
	}
}

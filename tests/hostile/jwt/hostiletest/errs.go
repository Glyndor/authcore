package hostiletest

import (
	"errors"

	"github.com/Glyndor/authcore/auth/jwt"
)

// IsInvalidOrMalformed reports the two sentinels a hostile token may fail
// with. Anything else, nil included, means it got further than it should.
func IsInvalidOrMalformed(err error) bool {
	return errors.Is(err, jwt.ErrTokenInvalid) || errors.Is(err, jwt.ErrTokenMalformed)
}

package parse

import (
	"fmt"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

// The range of seconds a time claim may hold: 1970-01-01T00:00:00Z up to
// 9999-12-31T23:59:59Z. A NumericDate outside it cannot have been written by
// this module, and a number too large for time.Time wraps to a date in the
// distant past, which the time checks would read as already elapsed.
const (
	minNumericDate int64 = 0
	maxNumericDate int64 = 253402300799
)

// checkDates refuses a token whose iat, nbf or exp lies outside the range
// above. It runs after the signature and the registered claims have been
// checked, so it only ever sees dates the issuer signed.
func checkDates(rc gjwt.RegisteredClaims) error {
	for name, d := range map[string]*gjwt.NumericDate{"iat": rc.IssuedAt, "nbf": rc.NotBefore, "exp": rc.ExpiresAt} {
		if d == nil {
			continue
		}
		if s := d.Unix(); s < minNumericDate || s > maxNumericDate {
			return fmt.Errorf("%w: %s claim is outside the supported date range", jwterr.ErrTokenInvalid, name)
		}
	}
	return nil
}

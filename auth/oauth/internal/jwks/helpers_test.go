package jwks

import "errors"

// ErrJWKS and ErrJWKSStale stand in for the public oauth sentinels of the same
// name, which the oauth package passes to New.
var (
	ErrJWKS      = errors.New("oauth: cannot obtain provider signing keys")
	ErrJWKSStale = errors.New("oauth: cached signing keys are stale and a refresh failed")

	testErrs = Errors{Fetch: ErrJWKS, Stale: ErrJWKSStale}
)

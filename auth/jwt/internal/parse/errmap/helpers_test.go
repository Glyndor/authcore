package errmap_test

import (
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

func newRig[T any](t *testing.T, cfg jwttest.Config) *jwttest.Rig[T] {
	t.Helper()
	return jwttest.NewRig[T](jwttest.NewKeys(t), cfg)
}

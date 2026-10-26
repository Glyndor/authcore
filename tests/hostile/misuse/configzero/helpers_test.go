package configzero

import (
	"context"
	"crypto/ed25519"
)

// nilDenylist is a Denylist whose methods are never reached: only a typed nil
// of it is used, to model a variable that was declared and never assigned.
type nilDenylist struct{}

func (*nilDenylist) IsRevoked(context.Context, string) (bool, error) { return false, nil }

func shortKey() []ed25519.PublicKey { return []ed25519.PublicKey{{1, 2, 3}} }

func zeroKey() []ed25519.PublicKey {
	return []ed25519.PublicKey{make(ed25519.PublicKey, ed25519.PublicKeySize)}
}

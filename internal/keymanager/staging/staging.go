// Package staging is the write half of the key publish transaction: it
// generates a key set into a private staging directory (subpackage createset)
// and hard-links the three files into the key directory in a fixed order
// (subpackage linkkeys), so that a crash at any point leaves a state recovery
// can finish or refuse. The refusal of a symlinked slot before anything is
// created lives in subpackage preflight.
package staging

import (
	"crypto/ed25519"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
	"github.com/Glyndor/authcore/internal/keymanager/staging/createset"
	"github.com/Glyndor/authcore/internal/keymanager/staging/linkkeys"
)

// ErrWaitAndLoad is the sentinel Publish returns when the private key link
// lost the race to another initialiser. The caller removes its own staging
// directory and waits for the winner to finish, then loads. It is the same
// value linkkeys.ErrWaitAndLoad carries.
var ErrWaitAndLoad = linkkeys.ErrWaitAndLoad

// Publish generates a fresh key set and publishes it into dir: the staging
// directory is created and synced, then the three files are linked into place.
// It returns the generated keys so the caller does not have to parse bytes it
// just wrote.
//
// ErrWaitAndLoad means another initialiser won the race for the private key
// link; the caller waits for the winner and loads its set instead.
func Publish(dir string, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	staging, priv, pub, secret, err := createset.Create(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := seams.Fault("staged"); err != nil {
		return nil, nil, nil, err
	}
	if err := linkkeys.Link(dir, staging, log); err != nil {
		return nil, nil, nil, err
	}
	return priv, pub, secret, nil
}

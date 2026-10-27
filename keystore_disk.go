package authcore

import (
	"github.com/Glyndor/authcore/internal/keystore/disk"
)

// diskKeyStore is the default KeyStore: it generates the key files on first run
// and loads them on subsequent runs, under dir. It preserves the zero-config
// secure-disk behaviour when Config.KeyStore is not set.
//
// When requireExisting is true, the store never writes: it expects the three
// key files to already be present and refuses to start otherwise. The flag
// is set from Config.RequireExistingKeys; see config.go for the contract.
type diskKeyStore struct {
	dir             string
	log             Logger
	requireExisting bool
}

func (d diskKeyStore) Load() (Keys, error) {
	km, err := disk.LoadDisk(d.dir, d.log, d.requireExisting)
	if err != nil {
		return nil, err
	}
	return km, nil
}

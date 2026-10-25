// Package disk is the default store behind the root package's KeyStore: it
// reaches the key manager that generates or loads the key files under a
// directory.
package disk

import "github.com/Glyndor/authcore/internal/keymanager"

// Logger is the logging surface the key manager reports through. It has the
// same method set as the root package's Logger.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// LoadDisk is the default store: it generates the key files on first run and
// loads them on subsequent runs, under dir.
//
// When requireExisting is true it never writes: it expects the three key
// files to already be present and refuses to start otherwise.
func LoadDisk(dir string, log Logger, requireExisting bool) (*keymanager.KeyManager, error) {
	if requireExisting {
		return keymanager.Load(dir, log)
	}
	return keymanager.New(dir, log)
}

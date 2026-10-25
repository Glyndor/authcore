// Package keysdir checks the keys directory named by the root package's
// Config.KeysDir before the key manager touches it.
package keysdir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// CheckDir ensures KeysDir exists (creating it if possible).
//
// It deliberately does NOT probe for writability. A read-only KeysDir is a
// valid and recommended deployment: pre-generated keys mounted read-only into
// a container (see docs/guides/key-management.md). Whether the directory needs to be
// written to depends on whether the key files already exist — that is the key
// manager's concern. When generation is actually required, the key manager
// surfaces a clear write error (wrapped as ErrKeyManager); when the keys are
// already present, no write happens and a read-only mount loads fine.
func CheckDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create keys directory %q: %w", dir, err)
	}
	return nil
}

// CheckLoadOnlyDir checks that dir exists and is a directory, without
// creating it. The check uses os.Stat, which follows symlinks: that is what a
// Kubernetes Secret mount needs (the Secret volume is a tree of symlinks).
//
// The zero value of KeysDir is replaced by applyDefaults before validateConfig
// runs in New, so by the time this function is called dir is non-empty.
//
// The error names the path and tells the operator how to recover. It is the
// config-side counterpart of the load-only keymanager error: both messages
// point at restoring the three key files from a backup.
func CheckLoadOnlyDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf(
				"key directory %q does not exist; authcore will not generate keys in "+
					"load-only mode. Provision ed25519_private.pem, ed25519_public.pem "+
					"and refresh_secret.key (restore them from a backup, or generate "+
					"them once without Config.RequireExistingKeys set) before starting",
				dir)
		}
		return fmt.Errorf("inspect key directory %q: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf(
			"keys directory %q is a %s, not a directory; load-only mode requires a "+
				"directory holding ed25519_private.pem, ed25519_public.pem and "+
				"refresh_secret.key",
			dir, fi.Mode().Type())
	}
	return nil
}

package keymanager

import (
	"fmt"
	"os"
	"path/filepath"
)

// This file holds the filesystem rules the key directory is written under.
// There are two of them and they deliberately point in opposite directions.
//
// Writes refuse to follow a symlink. Nothing legitimate creates a managed key
// file through a link, and following one hands an attacker who can write into
// KeysDir before authcore first runs a choice of where the freshly generated
// private key lands. That is not exotic for this library: a mounted container
// volume, a provisioning script, a restored backup or a Compose file can all
// populate the directory first.
//
// Reads keep following symlinks, and that is not an oversight. The documented
// Kubernetes deployment mounts a Secret at KeysDir, and Kubernetes projects a
// Secret volume as a tree of symlinks, so a loader that refused links would
// break every replica following the deployment guide in docs/key-management.md.
// Read-following is also the weaker exposure: the read path already caps the
// file at 4 KiB and validates the key pair, and a caller who can redirect a
// read can equally replace the file itself.

// fileState is what a presence check can conclude about a managed filename.
type fileState int

const (
	// fileAbsent means nothing exists at the path, not even a broken link.
	fileAbsent fileState = iota
	// filePresent means something exists that the loader can work with.
	filePresent
	// fileHostile means something exists that must not be written through.
	fileHostile
)

// inspect classifies a managed filename inside dir.
//
// It uses Stat, which resolves a symlink and so reports a dangling one as
// absent. That reads like the bug rather than the fix, and it was measured
// rather than assumed: a dangling link classified as absent sends the caller
// down the generate path and into createExclusive, which refuses it and says
// so, naming the link and what to do about it. Classifying it as present here
// instead makes the consistency check fire first, and that error tells the
// operator to "delete all key files", which since auth/field shipped is the
// advice that destroys every encrypted column. The worse message is not worth
// a control that O_EXCL already provides.
func inspect(dir, name string) (fileState, error) {
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fileAbsent, nil
	}
	if err != nil {
		return fileHostile, fmt.Errorf("inspecting %q: %w", path, err)
	}
	// Stat resolved any link, so fi describes the target and never carries
	// ModeSymlink. A link to a regular file is therefore present, which is the
	// Kubernetes case, and a link to anything else is refused with the rest.
	if fi.Mode().IsRegular() {
		return filePresent, nil
	}
	return fileHostile, fmt.Errorf(
		"%q is a %s, not a regular file; authcore refuses to treat it as key material",
		path, fi.Mode().Type())
}

// exists reports whether a managed filename has something the loader must
// deal with. A dangling symlink is not counted, for the reason inspect gives:
// it is refused at the write instead. A classification error is reported as
// present, a symlink loop being the case that is cheap to produce. Nothing
// generates on the strength of this answer: inspectKeySet decides that, and
// it returns the classification error itself. exists feeds the .gitignore
// check and the file lists in error messages.
func exists(dir, name string) bool {
	state, err := inspect(dir, name)
	return state != fileAbsent || err != nil
}

// createExclusive writes data to a file that must not already exist.
//
// O_CREATE|O_EXCL is the whole control, and it is the right one here because
// it is portable. It fails with EEXIST when the path is a symlink, dangling
// ones included, so the write cannot be redirected out of the key directory.
// O_NOFOLLOW would state the property more loudly but lives in syscall rather
// than os and is not defined on Windows, and this library ships to Windows
// consumers, so the portable flag that already has the property is the one to
// rely on.
//
// It also closes the narrower race the exclusion used to leave open: a regular
// file appearing between the presence check and the write kept its own
// permissions, so a 0644 file planted at that moment received the private key.
// Creation now fails instead.
func createExclusive(path string, data []byte, perm os.FileMode) error {
	// #nosec G304 -- path is KeysDir joined with a fixed managed filename, never request input
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf(
				"refusing to write %q: something already exists there. If it is a "+
					"symlink, authcore never writes key material through one: remove it "+
					"and let authcore create the file, or point KeysDir at the real "+
					"directory: %w", path, err)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

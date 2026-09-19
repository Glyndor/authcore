// Permission warning for secret files loaded from disk.
//
// A Podman secret mounted without an explicit `mode` arrives as a regular file
// with mode 0444 owned by root, and a Kubernetes Secret volume defaults to
// 0644. On 2026-09-19 authcore loaded the private key from such a file without
// a word. Refusing to load would break deployments that
// chose group access on purpose, and chmoding a file authcore did not create
// would override a deliberate operator choice, so the policy is: warn, never
// refuse, never chmod.

package keymanager

import (
	"os"
	"runtime"
)

// warnIfReadableByOthers logs a single Warn when path is readable by group or
// others. The check is a no-op on Windows, returns silently when path cannot be
// statted, and never changes the file's mode.
//
// It is called only for the private key and the refresh secret on the load
// paths; files authcore wrote itself at 0600 are skipped so a generation run
// cannot warn about its own output.
func warnIfReadableByOthers(path string, log logger) {
	// Go's permission bits do not describe Windows ACLs, so a warning there
	// would be noise.
	if runtime.GOOS == "windows" {
		return
	}

	// os.Stat follows symlinks: a Kubernetes Secret volume projects each
	// file as a symlink to the real path, and the mode that matters is the
	// target's. A stat failure here means the loader will surface its own
	// read error next, so reporting it now would duplicate the message.
	fi, err := os.Stat(path)
	if err != nil {
		return
	}

	// 0o044 is the group-read and other-read bits. The Podman default (0444)
	// and the Kubernetes default (0644) both set them.
	if fi.Mode().Perm()&0o044 != 0 {
		log.Warn(
			"authcore/keymanager: %s is readable by group or others "+
				"(mode %04o); restrict it to the process that uses it, "+
				"for example mode 0400 or 0600, or set mode and uid on the "+
				"Podman or Kubernetes secret",
			path, fi.Mode().Perm())
	}
}

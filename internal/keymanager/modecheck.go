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

// warnIfReadableByOthers logs a single Warn when path is readable or writable
// by group or others. The check is a no-op on Windows, returns silently when
// path cannot be statted, and never changes the file's mode. A writable secret
// is the worse case: until 2026-09-25 a refresh_secret.key at 0602 loaded
// silently while 0644 warned, and a file others can replace is a file whose
// contents are theirs.
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

	// 0o066 is the group and other read and write bits. The Podman default
	// (0444) and the Kubernetes default (0644) both set the read ones.
	if fi.Mode().Perm()&0o066 != 0 {
		log.Warn(
			"authcore/keymanager: %s is readable or writable by group or others "+
				"(mode %04o); restrict it to the process that uses it, "+
				"for example mode 0400 or 0600, or set mode and uid on the "+
				"Podman or Kubernetes secret",
			path, fi.Mode().Perm())
	}
}

// warnIfDirWritableByOthers logs a single Warn when dir can be written by
// group or others without the sticky bit, which is where a key file could be
// replaced. New tightens KeysDir to 0700; Load, the production path, never
// touched the directory and said nothing about it until 2026-09-25. A sticky
// 1777 directory is what Kubernetes mounts a Secret under, so it is not
// reported.
func warnIfDirWritableByOthers(dir string, log logger) {
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		log.Warn(
			"authcore/keymanager: key directory %s is writable by group or others "+
				"(mode %04o); anyone with that access can replace the key files. "+
				"Restrict it to the owner, for example mode 0700",
			dir, fi.Mode().Perm())
	}
}

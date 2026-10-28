package modecheck

import (
	"os"
	"sync"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// Keep directory identities for the process lifetime. SameFile recognises
// relative paths, parent symlinks and Windows path aliases without changing
// the path used by the key store or making assumptions about case folding.
var windowsNotices struct {
	sync.Mutex
	dirs []os.FileInfo
}

// needsWindowsNotice is the pure policy, independent of the host platform,
// filesystem and logger.
func needsWindowsNotice(goos string, alreadyWarned bool) bool {
	return goos == "windows" && !alreadyWarned
}

// WarnWindowsDirectory explains the permission limits once per directory per
// process, across creation and load-only calls. It never changes permissions.
// Unix calls return before inspecting the filesystem or recording a directory.
func WarnWindowsDirectory(dir string, log layout.Logger) {
	goos := seams.GOOS
	if !needsWindowsNotice(goos, false) {
		return
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return // the caller reports directory errors
	}

	windowsNotices.Lock()
	seen := false
	for _, previous := range windowsNotices.dirs {
		if os.SameFile(fi, previous) {
			seen = true
			break
		}
	}
	warn := needsWindowsNotice(goos, seen)
	if warn {
		windowsNotices.dirs = append(windowsNotices.dirs, fi)
	}
	windowsNotices.Unlock()

	// Call the configured logger outside the lock; it may call other code.
	if warn {
		log.Warn("authcore/keymanager: Windows does not enforce Unix mode bits; "+
			"key files in %q inherit ACLs from their parent directory. "+
			"The operator must restrict the key directory ACLs so only the service account can read it", dir)
	}
}

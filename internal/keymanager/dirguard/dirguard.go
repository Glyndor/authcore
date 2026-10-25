// Package dirguard refuses a key directory whose last path component is a
// symbolic link.
//
// The key directory is the one place authcore creates, tightens and writes
// into on behalf of the operator, so the path it is given must name the
// directory itself. A link as the final component sends every one of those
// writes to wherever the link points, which may be a directory the operator
// never meant to hold keys. Links in the parent components are not refused:
// a platform path such as /var resolving to /private/var is the same
// directory however it is spelled, and only the last component is a choice
// somebody made about this directory.
package dirguard

import (
	"os"
	"strings"

	"github.com/Glyndor/authcore/internal/keymanager/refusals"
)

// Refuse returns the refusal for dir when its last component is a symlink,
// and nil otherwise. A path that does not exist yet is not a link, and any
// other failure to inspect it is left to the code that opens dir, which
// reports it with its own context.
//
// Trailing separators and "." elements are dropped before the check, because
// the kernel resolves a link followed by "/" or "/." and Lstat would then
// describe the target instead of the link.
func Refuse(dir string) error {
	fi, err := os.Lstat(trimTrailing(dir))
	if err != nil {
		return nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return refusals.SymlinkKeysDir(dir)
	}
	return nil
}

// trimTrailing removes trailing path separators and "." elements, keeping at
// least one element.
func trimTrailing(p string) string {
	for {
		q := strings.TrimRightFunc(p, isSep)
		if q == "" || q == "." {
			return p
		}
		last := strings.LastIndexFunc(q, isSep)
		if q[last+1:] != "." {
			return q
		}
		p = q[:last+1]
	}
}

// isSep reports whether r separates path elements on this platform.
func isSep(r rune) bool { return r == '/' || r == os.PathSeparator }

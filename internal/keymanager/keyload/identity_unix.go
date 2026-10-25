//go:build unix

package keyload

import (
	"io/fs"
	"syscall"
)

// deviceAndInode returns the device and inode behind fi, or zeros when the
// platform does not report them.
func deviceAndInode(fi fs.FileInfo) (dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // the field types differ between unix platforms
	}
	return 0, 0
}

//go:build !unix

package keyload

import "io/fs"

// deviceAndInode reports nothing on a platform without them; size and
// modification time still identify a version of the file.
func deviceAndInode(fs.FileInfo) (dev, ino uint64) { return 0, 0 }

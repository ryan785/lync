//go:build !(linux || darwin || freebsd)

package rules

import "io/fs"

// fileOwner can't report POSIX owners on this platform (tests use Host.Meta).
func fileOwner(fi fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

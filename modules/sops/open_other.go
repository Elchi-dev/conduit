//go:build !unix

package sops

import "os"

// openFlags: Windows has no FIFOs in the file system; read re-checks the
// opened file is regular.
const openFlags = os.O_RDONLY

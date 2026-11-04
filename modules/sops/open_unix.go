//go:build unix

package sops

import (
	"os"
	"syscall"
)

// openFlags opens without blocking, so a FIFO put in a file's place is
// never waited on.
const openFlags = os.O_RDONLY | syscall.O_NONBLOCK

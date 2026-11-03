//go:build !windows

package update

import (
	"os"
	"syscall"
)

// Restart replaces this process with the binary at exe, keeping the PID (so
// service managers keep tracking it), arguments and environment.
func Restart(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}

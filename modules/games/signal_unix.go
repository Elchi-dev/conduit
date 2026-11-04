//go:build !windows

package games

import (
	"os/exec"
	"syscall"
)

// signalProc asks a process to quit (SIGTERM) or, with force, kills it.
func signalProc(pid int32, force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	return syscall.Kill(int(pid), sig)
}

// detach starts a launched game in its own session, so it outlives the
// daemon and doesn't receive the daemon's signals.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

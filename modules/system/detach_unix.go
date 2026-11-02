//go:build !windows

package system

import (
	"os/exec"
	"syscall"
)

// detach starts the process in its own session so it outlives the daemon.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

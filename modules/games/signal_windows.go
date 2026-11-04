//go:build windows

package games

import (
	"os/exec"
	"strconv"
	"syscall"
)

// signalProc asks a process to close (taskkill without /F sends the window a
// close message) or, with force, ends it and its children.
func signalProc(pid int32, force bool) error {
	args := []string{"/PID", strconv.Itoa(int(pid)), "/T"}
	if force {
		args = append(args, "/F")
	}
	cmd := exec.Command("taskkill", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// detach starts a launched game in its own process group, so it outlives the
// daemon and doesn't receive its console signals.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

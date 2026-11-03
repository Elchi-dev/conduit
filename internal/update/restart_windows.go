//go:build windows

package update

import (
	"os"
	"os/exec"
)

// Restart starts the binary at exe with the same arguments and exits. The
// new process retries its listen address until this one has let go.
func Restart(exe string) error {
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

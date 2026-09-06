//go:build !windows

package cli

import (
	"io"
	"os/exec"
)

func runCommandWithPlatformStreams(cmd *exec.Cmd, stdout, stderr io.Writer, afterStart ...func()) error {
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	for _, started := range afterStart {
		if started != nil {
			started()
		}
	}
	return cmd.Wait()
}

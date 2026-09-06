package cli

import (
	"io"
	"os/exec"
)

func runSSHCommandWithLocalDiagnostics(cmd *exec.Cmd, stdout, stderr io.Writer, afterStart ...func()) (bool, error) {
	return false, runSSHCommand(cmd, stdout, stderr, afterStart...)
}

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunWorkloadStdinAcrossCommandModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake SSH subprocess")
	}
	for _, mode := range []string{"argv", "shell", "script", "script-stdin", "nil"} {
		t.Run(mode, func(t *testing.T) {
			clearConfigEnv(t)
			dir := t.TempDir()
			isolateRunTestUserDirs(t, dir)
			t.Setenv("CRABBOX_CONFIG", filepath.Join(dir, "missing.yaml"))
			t.Setenv("CRABBOX_FAKE_SSH_PORT", "22")
			t.Setenv("CRABBOX_FAKE_SSH_PROXY", "1")
			ssh := `#!/bin/sh
remote=
noinput=
for arg do
  remote="$arg"
  if [ "$arg" = -n ]; then noinput=1; fi
done
if [ -n "$noinput" ]; then exec 0</dev/null; fi
case "$remote" in
  *CRABBOX_RUN_ID*)
    /bin/cat
    printf 'workload stderr\n' >&2
    exit 37
    ;;
esac
# Deliberately read every control invocation: only its own upload data, never
# borrowed workload input, may be available here.
/bin/cat >/dev/null
exit 0
`
			if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(ssh), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			payload := []byte{0, 1, 2, '\n', '\r', 127, 128, 255, 'x'}
			var stdin io.Reader = bytes.NewReader(payload)
			expected := payload
			stdoutPath, stderrPath := filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
			args := []string{"--provider", "run-env-profile-test", "--no-sync", "--no-hydrate",
				"--capture-stdout", stdoutPath, "--capture-stderr", stderrPath}
			switch mode {
			case "shell":
				args = append(args, "--shell", "--", "cat; exit 37")
			case "script":
				script := filepath.Join(dir, "probe.sh")
				if err := os.WriteFile(script, []byte("#!/bin/sh\ncat\nexit 37\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--script", script)
			case "script-stdin":
				stdin = strings.NewReader("#!/bin/sh\ncat\nexit 37\n")
				expected = nil
				args = append(args, "--script-stdin")
			default:
				args = append(args, "--", "cat")
				if mode == "nil" {
					stdin, expected = nil, nil
				}
			}
			var stdout, stderr bytes.Buffer
			err := (App{Stdin: stdin, Stdout: &stdout, Stderr: &stderr}).runCommand(t.Context(), args)
			var result ExitError
			if !errors.As(err, &result) || result.Code != 37 {
				t.Fatalf("exit=%d err=%v stderr=%s", result.Code, err, stderr.String())
			}
			actual, err := os.ReadFile(stdoutPath)
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatalf("stdout=%x want=%x err=%v", actual, expected, err)
			}
			actual, err = os.ReadFile(stderrPath)
			if err != nil || string(actual) != "workload stderr\n" {
				t.Fatalf("stderr=%q err=%v", actual, err)
			}
		})
	}
}

func TestSSHWorkloadStdinDoesNotWaitForBorrowedReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake SSH subprocess")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nprintf 'done\\n'\nexit 37\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var output bytes.Buffer
	code, err := runSSHStreamResult(ctx, SSHTarget{Host: "127.0.0.1", User: "test", Port: "22", NoControlMaster: true}, "exit 37", input, &output, io.Discard)
	if code != 37 || output.String() != "done\n" || ctx.Err() != nil {
		t.Fatalf("code=%d err=%v output=%q context=%v", code, err, output.String(), ctx.Err())
	}
}

func TestSSHWorkloadStdinCancellationKeepsBorrowedFileOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake SSH subprocess")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	code, err := runSSHStreamResult(ctx, SSHTarget{Host: "127.0.0.1", User: "test", Port: "22", NoControlMaster: true}, "sleep 60", input, io.Discard, io.Discard)
	if code == 0 || err == nil || ctx.Err() == nil {
		t.Fatalf("cancel code=%d err=%v context=%v", code, err, ctx.Err())
	}
	if _, err := input.Stat(); err != nil {
		t.Fatalf("borrowed stdin closed: %v", err)
	}
}

func TestSSHWorkloadStdinDoesNotReplayAfterMuxFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake SSH subprocess")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	t.Setenv("CRABBOX_STDIN_CALLS", log)
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(`#!/bin/sh
printf 'call\n' >> "$CRABBOX_STDIN_CALLS"
/bin/cat >/dev/null
printf 'mm_send_fd: sendmsg(0): Broken pipe\nmux_client_request_session: send fds failed\n' >&2
exit 255
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	code, err := runSSHStreamResult(t.Context(), SSHTarget{Host: "127.0.0.1", User: "test", Port: "22"}, "cat", strings.NewReader("do not replay"), io.Discard, io.Discard)
	if code != 255 || err == nil {
		t.Fatalf("code=%d err=%v", code, err)
	}
	data, err := os.ReadFile(log)
	if err != nil || string(data) != "call\n" {
		t.Fatalf("workload replayed: calls=%q err=%v", data, err)
	}
}

func TestSSHWorkloadStdinFailedLaunchDoesNotReadOrLeak(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux descriptor ownership observation")
	}
	for _, phase := range []string{"diagnostics", "exec"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			program := "#!/bin/sh\nexit 0\n"
			if phase == "exec" {
				program = "#!/crabbox-missing-stdin-test-interpreter\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(program), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			if phase == "diagnostics" {
				blocked := filepath.Join(dir, "not-a-directory")
				if err := os.WriteFile(blocked, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("TMPDIR", blocked)
			}
			// Initialize Go's descriptor poller before comparing owned FDs.
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
			_ = w.Close()
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			input := &unlaunchedWorkloadReader{}
			for range 8 {
				code, err := runSSHStreamResult(t.Context(), SSHTarget{
					Host: "127.0.0.1", User: "test", Port: "22", NoControlMaster: phase == "exec",
				}, "cat", input, io.Discard, io.Discard)
				if code == 0 || err == nil {
					t.Fatalf("%s unexpectedly launched: code=%d err=%v", phase, code, err)
				}
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if len(after) > len(before) {
				t.Fatalf("failed %s leaked descriptors: before=%d after=%d", phase, len(before), len(after))
			}
			if input.reads.Load() != 0 {
				t.Fatalf("failed %s consumed input before launch", phase)
			}
		})
	}
}

type unlaunchedWorkloadReader struct{ reads atomic.Int32 }

func (r *unlaunchedWorkloadReader) Read([]byte) (int, error) {
	r.reads.Add(1)
	return 0, io.EOF
}

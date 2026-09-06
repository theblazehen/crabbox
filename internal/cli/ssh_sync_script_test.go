package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type syncScriptSSHFixture struct {
	root   string
	target SSHTarget
}

func newSyncScriptSSHFixture(t *testing.T, mode string) syncScriptSSHFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX SSH shell fixture")
	}
	root := t.TempDir()
	clearConfigEnv(t)
	isolateRunTestUserDirs(t, root)
	// Execute real upload, script and cleanup shells. The fixture only injects
	// transport failures or a competing allocation; it never interprets source.
	ssh := `#!/bin/sh
for arg do
  if [ "$arg" = -G ]; then
    printf 'hostname fixture.invalid\nuser fixture\nport 22\n'
    exit 0
  fi
done
for remote do :; done
port=
previous=
for arg do
  if [ "$previous" = -p ]; then port=$arg; fi
  previous=$arg
done
printf '%s\n' "$port" >> "$CRABBOX_SYNC_FIXTURE/ports"
count=0
if [ -f "$CRABBOX_SYNC_FIXTURE/count" ]; then count=$(cat "$CRABBOX_SYNC_FIXTURE/count"); fi
count=$((count + 1))
printf '%s' "$count" > "$CRABBOX_SYNC_FIXTURE/count"
printf '%s\n' "${#remote}" >> "$CRABBOX_SYNC_FIXTURE/lengths"
dir=$(printf '%s' "$remote" | sed -n 's|.*\(/tmp/crabbox-sync-script-[0-9a-f]*\).*|\1|p' | sed -n '1p')
if [ -n "$dir" ] && [ ! -s "$CRABBOX_SYNC_FIXTURE/dir" ]; then
  printf '%s' "$dir" > "$CRABBOX_SYNC_FIXTURE/dir"
fi
if [ "$count" = 1 ]; then
  case "$CRABBOX_SYNC_MODE" in
    collision)
      mkdir "$dir" || exit 90
      printf 'not ours' > "$dir/sentinel"
      ;;
    symlink)
      mkdir "$CRABBOX_SYNC_FIXTURE/foreign" || exit 90
      printf 'not ours' > "$CRABBOX_SYNC_FIXTURE/foreign/sentinel"
      ln -s "$CRABBOX_SYNC_FIXTURE/foreign" "$dir" || exit 90
      ;;
    upload-fail)
      printf 'partial shell source' | /bin/sh -c "$remote" || exit 91
      exit 41
      ;;
  esac
fi
if [ "$CRABBOX_SYNC_MODE" = fallback ] && [ "$port" = 2222 ]; then
  printf 'ssh: connect to host fixture.invalid port 2222: Connection refused\n' >&2
  exit 255
fi
if [ "$count" = 2 ] && [ "$CRABBOX_SYNC_MODE" = cancel ]; then
  printf 'started'
  exec /bin/sleep 30
fi
if [ "$count" = 3 ] && [ "$CRABBOX_SYNC_MODE" = cleanup-fail ]; then
  printf 'cleanup refused\n' >&2
  exit 42
fi
exec /bin/sh -c "$remote"
`
	if err := os.WriteFile(filepath.Join(root, "ssh"), []byte(ssh), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CRABBOX_SYNC_FIXTURE", root)
	t.Setenv("CRABBOX_SYNC_MODE", mode)
	t.Cleanup(func() {
		data, err := os.ReadFile(filepath.Join(root, "dir"))
		if err == nil && strings.HasPrefix(string(data), "/tmp/crabbox-sync-script-") {
			if err := os.RemoveAll(string(data)); err != nil {
				t.Error(err)
			}
		}
	})
	return syncScriptSSHFixture{root: root, target: SSHTarget{
		User: "fixture", Host: "fixture.invalid", Port: "22", TargetOS: targetLinux,
		NoControlMaster: true,
	}}
}

func (f syncScriptSSHFixture) stagingDir(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, "dir"))
	if err != nil || len(data) == 0 {
		t.Fatalf("staging path: %q, %v", data, err)
	}
	return string(data)
}

func (f syncScriptSSHFixture) assertRemoved(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat(f.stagingDir(t)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging directory remains: %v", err)
	}
}

func TestSSHSyncScriptLargeSourcePreservesBinaryInputAndExit(t *testing.T) {
	f := newSyncScriptSSHFixture(t, "normal")
	input := bytes.Repeat([]byte{0, 255, '\n', '\r', '"', '\''}, 4096)
	source := "# " + strings.Repeat("large generated source ", 2048) + "\n" +
		"/bin/cat\nprintf 'separate stderr' >&2\nexit 37\n"
	var stdout, stderr bytes.Buffer
	err := runSSHSyncScriptInput(t.Context(), f.target, source, bytes.NewReader(input), &stdout, &stderr)
	if exitCode(err) != 37 || !bytes.Equal(stdout.Bytes(), input) || stderr.String() != "separate stderr" {
		t.Fatalf("exit=%d err=%v stdout bytes=%d stderr=%q", exitCode(err), err, stdout.Len(), stderr.String())
	}
	f.assertRemoved(t)
	f.assertShortRequests(t)
}

func (f syncScriptSSHFixture) assertShortRequests(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, "lengths"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range strings.Fields(string(data)) {
		length, err := strconv.Atoi(text)
		if err != nil || length >= 9000 {
			t.Fatalf("SSH exec request length=%q: %v", text, err)
		}
	}
}

func TestSSHSyncScriptCombinedOutputAndSuccessCleanup(t *testing.T) {
	f := newSyncScriptSSHFixture(t, "normal")
	out, err := runSSHSyncScriptCombinedOutput(t.Context(), f.target, "printf ' stdout '; printf ' stderr ' >&2")
	if err != nil || !strings.Contains(out, "stdout") || !strings.Contains(out, "stderr") || out != strings.TrimSpace(out) {
		t.Fatalf("combined output=%q err=%v", out, err)
	}
	f.assertRemoved(t)
}

func TestSSHSyncScriptStagesAndEnforcesWorkspaceWitness(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(strconv.FormatBool(valid), func(t *testing.T) {
			f := newSyncScriptSSHFixture(t, "normal")
			key := workspaceOwnerKey("cbx_uploaded_sync_script")
			token := strings.Repeat("a", 64)
			request := workspaceOwnerRemoteRequest{Action: workspaceOwnerAcquire, Key: key, Token: token, TTL: time.Minute}
			if out, err := runPOSIXWorkspaceOwnerScript(t, os.Getenv("HOME"), remoteWorkspaceOwnerPOSIX(request)); err != nil || out != "ACQUIRED" {
				t.Fatalf("acquire workspace owner: %q %v", out, err)
			}
			if !valid {
				token = strings.Repeat("b", 64)
			}
			owner := &workspaceOwner{target: f.target, key: key, token: token}
			ctx := contextWithWorkspaceOwner(t.Context(), owner)
			marker := filepath.Join(f.root, "guarded-command-ran")
			source := "# " + strings.Repeat("generated sync source ", 1024) + "\n" +
				"printf ran > " + shellQuote(marker) + "\n/bin/cat\nexit 37\n"
			input := []byte{'a', 0, 255, '\n', 'b'}
			var stdout, stderr bytes.Buffer
			err := runSSHSyncScriptInput(ctx, f.target, source, bytes.NewReader(input), &stdout, &stderr)
			if valid {
				if exitCode(err) != 37 || !bytes.Equal(stdout.Bytes(), input) || stderr.Len() != 0 {
					t.Fatalf("guarded execution: err=%v stdout=%q stderr=%q", err, stdout.Bytes(), stderr.String())
				}
				if data, err := os.ReadFile(marker); err != nil || string(data) != "ran" {
					t.Fatalf("guarded source did not run: %q %v", data, err)
				}
			} else {
				var setupErr *workspaceOwnerSetupError
				if !errors.As(err, &setupErr) {
					t.Fatalf("ownership refusal lost setup classification: %v; stderr=%q", err, stderr.String())
				}
				if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("wrong owner executed source: %v", err)
				}
			}
			f.assertRemoved(t)
			f.assertShortRequests(t)
		})
	}
}

func TestSSHSyncScriptRetainsFallbackPortAcrossPhases(t *testing.T) {
	f := newSyncScriptSSHFixture(t, "fallback")
	f.target.Port = "2222"
	f.target.FallbackPorts = []string{"22"}
	var stdout bytes.Buffer
	err := runSSHSyncScriptInputTarget(t.Context(), &f.target, "printf resolved", nil, &stdout, io.Discard)
	if err != nil || stdout.String() != "resolved" || f.target.Port != "22" {
		t.Fatalf("fallback err=%v output=%q target=%+v", err, stdout.String(), f.target)
	}
	f.assertRemoved(t)
	data, err := os.ReadFile(filepath.Join(f.root, "ports"))
	if err != nil {
		t.Fatal(err)
	}
	ports := strings.Fields(string(data))
	if len(ports) < 4 || ports[0] != "2222" {
		t.Fatalf("fallback attempts=%q", ports)
	}
	for _, port := range ports[1:] {
		if port != "22" {
			t.Fatalf("resolved port lost across phases: %q", ports)
		}
	}
}

func TestSSHSyncScriptBackgroundWitnessOutlivesStaging(t *testing.T) {
	f := newSyncScriptSSHFixture(t, "normal")
	home := os.Getenv("HOME")
	key := workspaceOwnerKey("cbx_uploaded_background_witness")
	token := strings.Repeat("c", 64)
	request := workspaceOwnerRemoteRequest{Action: workspaceOwnerAcquire, Key: key, Token: token, TTL: time.Minute}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(request)); err != nil || out != "ACQUIRED" {
		t.Fatalf("acquire workspace owner: %q %v", out, err)
	}
	owner := &workspaceOwner{target: f.target, key: key, token: token}
	childPath := filepath.Join(home, ".crabbox", "workspace-owners", key+".child")
	defer func() {
		if out, err := runPOSIXWorkspaceOwnerScript(t, home, owner.rsyncStopCommand()); err != nil {
			t.Errorf("stop detached witness: %q %v", out, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(childPath); errors.Is(err, os.ErrNotExist) {
				break
			}
			if time.Now().After(deadline) {
				t.Error("detached witness did not clear after its stop request")
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	out, err := runWorkspaceOwnerBackgroundOutput(t.Context(), f.target, owner, owner.rsyncGuardPayload(filepath.Join(home, "rsync-destination")))
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("launch detached witness: %q %v", out, err)
	}
	f.assertRemoved(t)
	f.assertShortRequests(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(childPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("detached witness did not become live after launcher returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	request.Action = workspaceOwnerInspect
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(request)); err != nil || out != "CHILD" {
		t.Fatalf("staged launcher lost live ownership witness: %q %v", out, err)
	}
}

type syncScriptUnreadInput struct {
	read bool
}

func (r *syncScriptUnreadInput) Read([]byte) (int, error) {
	r.read = true
	return 0, io.EOF
}

func TestSSHSyncScriptFailedUploadDoesNotExecuteOrReadInput(t *testing.T) {
	f := newSyncScriptSSHFixture(t, "upload-fail")
	marker := filepath.Join(f.root, "executed")
	input := &syncScriptUnreadInput{}
	err := runSSHSyncScriptInput(t.Context(), f.target, "touch "+shellQuote(marker), input, io.Discard, io.Discard)
	if exitCode(err) != 41 || input.read {
		t.Fatalf("err=%v input read=%t", err, input.read)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source executed after upload failure: %v", err)
	}
	f.assertRemoved(t)
}

func TestSSHSyncScriptCollisionNeverRemovesExistingPaths(t *testing.T) {
	for _, mode := range []string{"collision", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			f := newSyncScriptSSHFixture(t, mode)
			input := &syncScriptUnreadInput{}
			err := runSSHSyncScriptInput(t.Context(), f.target, "exit 0", input, io.Discard, io.Discard)
			if err == nil || input.read {
				t.Fatalf("collision err=%v input read=%t", err, input.read)
			}
			data, err := os.ReadFile(filepath.Join(f.stagingDir(t), "sentinel"))
			if err != nil || string(data) != "not ours" {
				t.Fatalf("collision contents changed: %q %v", data, err)
			}
		})
	}
}

func TestSSHSyncScriptCleanupFailurePreservesExecutionResult(t *testing.T) {
	for _, code := range []int{0, 37} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			f := newSyncScriptSSHFixture(t, "cleanup-fail")
			var stderr bytes.Buffer
			err := runSSHSyncScriptInput(t.Context(), f.target, "exit "+strconv.Itoa(code), nil, io.Discard, &stderr)
			wantCode := code
			if wantCode == 0 {
				wantCode = 42
			}
			if err == nil || exitCode(err) != wantCode || !strings.Contains(err.Error(), "clean up uploaded sync script") || !strings.Contains(stderr.String(), "cleanup refused") {
				t.Fatalf("cleanup err=%v exit=%d stderr=%q", err, exitCode(err), stderr.String())
			}
		})
	}
}

type syncScriptCancelWriter struct {
	cancel context.CancelCauseFunc
	cause  error
}

func (w syncScriptCancelWriter) Write(p []byte) (int, error) {
	w.cancel(w.cause)
	return len(p), nil
}

func TestSSHSyncScriptCancellationKeepsCauseAndCleans(t *testing.T) {
	f := newSyncScriptSSHFixture(t, "cancel")
	deadline, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	ctx, cancel := context.WithCancelCause(deadline)
	defer cancel(nil)
	cause := errors.New("sync cancelled by caller")
	err := runSSHSyncScriptInput(ctx, f.target, "exit 0", nil, syncScriptCancelWriter{cancel: cancel, cause: cause}, io.Discard)
	if !errors.Is(err, cause) {
		t.Fatalf("cancellation cause lost: %v", err)
	}
	f.assertRemoved(t)
}

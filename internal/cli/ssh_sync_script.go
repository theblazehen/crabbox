package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// runSSHSyncScriptInput keeps generated shell source out of the SSH exec
// request, leaving the execution session's stdin exclusively for sync data.
func runSSHSyncScriptInput(ctx context.Context, target SSHTarget, remote string, input io.Reader, stdout, stderr io.Writer) error {
	if target.TargetOS == targetWindows {
		return runSSHInput(ctx, target, remote, input, stdout, stderr)
	}
	return runSSHSyncScriptInputTarget(ctx, &target, remote, input, stdout, stderr)
}

// The pointer form retains a discovered fallback port across Git's outer retry
// loop as well as across upload, execution and cleanup of this script.
func runSSHSyncScriptInputTarget(ctx context.Context, target *SSHTarget, remote string, input io.Reader, stdout, stderr io.Writer) (err error) {
	if target.TargetOS == targetWindows {
		return executeSSHSyncScriptInput(ctx, target, remote, input, stdout, stderr)
	}
	// POSIX ownership preparation needs only stdin's presence, not its length.
	// Keep that witness inside the uploaded source so neither it nor the sync
	// program can enlarge the exec request. Manifest input is not read yet.
	var inputSize *int64
	var sizeHint int64
	if input != nil {
		inputSize = &sizeHint
	}
	prepared, err := prepareWorkspaceOwnerRemote(ctx, *target, remote, inputSize)
	if err != nil {
		return sshPreparationError{err}
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, prepared.close(ctx, *target))
		}
	}()
	name, err := randomHex(16)
	if err != nil {
		return fmt.Errorf("create sync script name: %w", err)
	}
	owner, err := randomHex(32)
	if err != nil {
		return fmt.Errorf("create sync script ownership token: %w", err)
	}
	// Never stage executable source beneath the checkout or honor its TMPDIR.
	// mkdir is exclusive; the independent token also fences cleanup after an
	// upload whose acknowledgement was lost, without deleting a collision.
	dir := "/tmp/crabbox-sync-script-" + name
	defer func() {
		if err != nil && context.Cause(ctx) != nil {
			err = errors.Join(err, context.Cause(ctx))
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		cleanupErr := executePreparedSSH(cleanupCtx, target, remoteCleanupSyncScript(dir, owner), nil, 0, sshCommandLimit{}, "10", "3", io.Discard, stderr)
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("clean up uploaded sync script: %w", cleanupErr))
		}
	}()
	// Staging touches only this exclusive private directory, not the workspace.
	// It must not acquire another copy of the workspace witness wrapper.
	if err = executePreparedSSH(ctx, target, remoteUploadSyncScript(dir, owner), strings.NewReader(prepared.command), int64(len(prepared.command)), sshCommandLimit{}, "10", "3", io.Discard, stderr); err != nil {
		return fmt.Errorf("upload sync script: %w", err)
	}
	var source io.ReadSeeker
	var size int64
	if input != nil {
		data, readErr := io.ReadAll(input)
		if readErr != nil {
			return readErr
		}
		source, size = bytes.NewReader(data), int64(len(data))
	}
	transport, err := prepareSSHTransport(*target, "/bin/sh "+shellQuote(dir+"/script"), source, size, sshCommandLimit{})
	if err != nil {
		return sshPreparationError{err}
	}
	transport.setupMarker = prepared.setupMarker
	return transport.execute(ctx, target, sshCommandLimit{}, "10", "3", stdout, stderr)
}

func executeSSHSyncScriptInput(ctx context.Context, target *SSHTarget, remote string, input io.Reader, stdout, stderr io.Writer) error {
	if input == nil {
		return executeSSH(ctx, target, remote, nil, 0, 0, "10", "3", stdout, stderr)
	}
	// Match runSSHInput's replayable reader semantics, without copying the
	// generated source or allocating an empty input for command-only callers.
	data, err := io.ReadAll(input)
	if err != nil {
		return err
	}
	return executeSSH(ctx, target, remote, bytes.NewReader(data), int64(len(data)), 0, "10", "3", stdout, stderr)
}

func runSSHSyncScriptCombinedOutput(ctx context.Context, target SSHTarget, remote string) (string, error) {
	if target.TargetOS == targetWindows {
		return runSSHCombinedOutput(ctx, target, remote)
	}
	var out synchronizedBuffer
	err := runSSHSyncScriptInput(ctx, target, remote, nil, &out, &out)
	return strings.TrimSpace(out.String()), err
}

func remoteUploadSyncScript(dir, owner string) string {
	script := "set -eu\numask 077\n" +
		"dir=" + shellQuote(dir) + "\n" +
		"/bin/mkdir \"$dir\"\n" +
		"trap 'status=$?; trap - 0; /bin/rm -f \"$dir/script\" \"$dir/owner\" && /bin/rmdir \"$dir\"; exit \"$status\"' 0\n" +
		"trap 'exit 129' HUP\ntrap 'exit 130' INT\ntrap 'exit 143' TERM\n" +
		"set -C\n" +
		"printf '%s\\n' " + shellQuote(owner) + " > \"$dir/owner\"\n" +
		"/bin/cat > \"$dir/script\"\n" +
		"trap - 0\n"
	return "/bin/sh -c " + shellQuote(script)
}

func remoteCleanupSyncScript(dir, owner string) string {
	// Do not recursively remove a tree, or follow a replacement directory or
	// marker symlink. Unknown contents are a cleanup error, not ours to delete.
	script := "set -eu\n" +
		"dir=" + shellQuote(dir) + "\n" +
		"if [ ! -e \"$dir\" ] && [ ! -L \"$dir\" ]; then exit 0; fi\n" +
		"[ ! -L \"$dir\" ] && [ -d \"$dir\" ] && [ ! -L \"$dir/owner\" ] && [ -f \"$dir/owner\" ] || exit 1\n" +
		"[ \"$(/bin/cat \"$dir/owner\")\" = " + shellQuote(owner) + " ] || exit 1\n" +
		"/bin/rm -f \"$dir/script\"\n" +
		"/bin/rm \"$dir/owner\"\n" +
		"/bin/rmdir \"$dir\"\n"
	return "/bin/sh -c " + shellQuote(script)
}

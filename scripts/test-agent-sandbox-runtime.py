#!/usr/bin/env python3
"""Exercise generated Agent Sandbox runtime assets in disposable Docker images.

Run on the Crabbox Linux runner with host-network Docker access, OpenSSH clients,
rsync, and the generated native amd64 assets. No image packages are installed.
"""

import argparse
import base64
import contextlib
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid


class SmokeFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def diagnostic_tail(data):
    if not data:
        return ""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    text = re.sub(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
        "[private key redacted]", text, flags=re.DOTALL,
    )
    return text[-8192:].strip()


def failure_message(message, stderr, stdout=None):
    detail = diagnostic_tail(stderr)
    output = diagnostic_tail(stdout)
    return message + ("\nstderr:\n" + detail if detail else "") + ("\nstdout:\n" + output if output else "")


def run(args, *, data=None, timeout=90, check=True, cwd=None, env=None):
    """Retain the exact harness command and bounded output when execution fails."""
    command = shlex.join([str(arg) for arg in args])
    try:
        result = subprocess.run(
            [str(arg) for arg in args], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False, cwd=cwd, env=env,
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeFailure(failure_message(f"{command} exceeded {timeout}s", error.stderr, error.stdout)) from error
    if check and result.returncode:
        raise SmokeFailure(failure_message(f"{command} failed with exit {result.returncode}", result.stderr, result.stdout))
    return result


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def key_pair(directory, name):
    key = directory / name
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key])
    return key, canonical_key(key.with_suffix(".pub").read_text())


def canonical_key(text):
    words = text.strip().split()
    require(len(words) >= 2 and words[0] == "ssh-ed25519", "expected an ed25519 public key")
    try:
        wire = base64.b64decode(words[1], validate=True)
    except ValueError as error:
        raise SmokeFailure("invalid public-key encoding") from error
    require(len(wire) == 51 and wire[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20", "invalid ed25519 key wire format")
    return " ".join(words[:2])


def parse_endpoint(data):
    try:
        text = data.decode("utf-8")
        lines = text.splitlines()
        require(len(lines) == 3 and text.endswith("\n") and "\r" not in text, "initializer returned extra or malformed output")
        require(lines[0] == "CRABBOX_SSH_USER=root", "initializer did not return root")
        require(lines[1].startswith("CRABBOX_SSH_HOST_KEY="), "initializer host-key marker missing")
        require(lines[2].startswith("CRABBOX_SSH_PORT="), "initializer port marker missing")
        key = canonical_key(lines[1].split("=", 1)[1])
        value = lines[2].split("=", 1)[1]
        port = int(value)
        require(str(port) == value and 1024 <= port <= 65535, "initializer returned invalid port")
        return key, port
    except (UnicodeError, ValueError) as error:
        raise SmokeFailure("initializer endpoint could not be parsed") from error


def tar_snapshot(data):
    """Record existing inode metadata and bytes, without exposing their contents."""
    records = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            path = member.name.rstrip("/")
            require(path not in records, "duplicate snapshot archive entry")
            digest = None
            if member.isfile():
                stream = archive.extractfile(member)
                require(stream is not None, "snapshot file has no contents")
                with stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
            # Directory mtime changes legitimately when new tools are added.
            records[path] = (
                member.type, member.mode, member.uid, member.gid,
                None if member.isdir() else member.mtime,
                member.linkname, digest,
            )
    return records


def snapshot(container):
    result = {}
    for path in ("/bin", "/usr/bin", "/bin/.", "/usr/bin/."):
        result[path] = tar_snapshot(docker("cp", f"{container}:{path}", "-").stdout)
    for path in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/shells"):
        exists = docker("exec", container, "/bin/sh", "-c", '[ -e "$1" ] || [ -L "$1" ]', "sh", path, check=False)
        require(exists.returncode in (0, 1), "could not inspect account-file presence")
        result[path] = None if exists.returncode else tar_snapshot(docker("cp", f"{container}:{path}", "-").stdout)
    return result


def assert_unchanged(before, after):
    for root, records in before.items():
        current = after[root]
        if records is None:
            require(current is None, f"initializer created previously absent account file {root}")
            continue
        require(current is not None, f"initializer removed {root}")
        for path, record in records.items():
            require(current.get(path) == record, f"initializer changed pre-existing path {root}: {path}")
        if root.startswith("/etc/"):
            require(current == records, f"initializer changed account-file archive {root}")


def extract_fixture_tools(payload, destination):
    """Copy only the two real bundled daemon binaries, following archive aliases."""
    with tarfile.open(payload, "r:gz") as archive:
        members = {member.name.removeprefix("./"): member for member in archive}
        for name in ("dropbear", "dropbearkey"):
            current = f"bin/{name}"
            visited = set()
            while True:
                require(current not in visited, "cyclic payload binary alias")
                visited.add(current)
                member = members.get(current)
                require(member is not None, f"payload lacks {name}")
                if member.issym() or member.islnk():
                    require(not member.linkname.startswith("/"), "absolute payload alias")
                    current = os.path.normpath(str(Path(current).parent / member.linkname) if member.issym() else member.linkname)
                    require(current != ".." and not current.startswith("../"), "payload alias escapes archive")
                    continue
                require(member.isfile(), "payload binary is not a regular file")
                stream = archive.extractfile(member)
                require(stream is not None, "payload binary has no contents")
                with stream, (destination / name).open("wb") as output:
                    shutil.copyfileobj(stream, output)
                (destination / name).chmod(0o755)
                break


def ssh_options(key, known_hosts, alias, port):
    return [
        "-F", "/dev/null", "-i", str(key),
        "-o", f"Port={port}", "-o", f"HostKeyAlias={alias}",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "ProxyCommand=none",
        "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1",
    ]


def ssh_command(options, command, **kwargs):
    return run(["ssh", *options, "root@127.0.0.1", command], **kwargs)


def wait_ssh(options, marker, deadline=15):
    end = time.monotonic() + deadline
    stderr = b""
    stdout = b""
    command = ""
    while time.monotonic() < end:
        result = ssh_command(options, f"printf %s {shlex.quote(marker)}", check=False, timeout=5)
        if result.returncode == 0 and result.stdout == marker.encode():
            return
        stderr = result.stderr
        stdout = result.stdout
        command = shlex.join(result.args)
        time.sleep(0.1)
    raise SmokeFailure(failure_message("private SSH endpoint did not accept its pinned lease key; last command: " + command, stderr, stdout))


@contextlib.contextmanager
def child_process(args):
    # Diagnostics remain private in this temporary file (not an unconsumed pipe).
    with tempfile.TemporaryFile() as diagnostic:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=diagnostic, stderr=diagnostic)
        try:
            yield process
        except SmokeFailure as error:
            diagnostic.seek(0)
            raise SmokeFailure(failure_message(str(error) + "; process: " + shlex.join(args), diagnostic.read())) from error
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            else:
                process.wait()


def forwarding_smoke(options):
    marker = b"crabbox-real-ssh-local-forward\n"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(marker)))
            self.end_headers()
            self.wfile.write(marker)

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 1
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            local_port = reservation.getsockname()[1]
        args = ["ssh", *options, "-o", "ExitOnForwardFailure=yes", "-N", "-L",
                f"127.0.0.1:{local_port}:127.0.0.1:{server.server_port}", "root@127.0.0.1"]
        with child_process(args) as process:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            end = time.monotonic() + 15
            while time.monotonic() < end:
                require(process.poll() is None, "SSH local-forward process exited before readiness")
                try:
                    with opener.open(f"http://127.0.0.1:{local_port}/", timeout=2) as response:
                        require(response.read() == marker, "SSH forward returned incorrect HTTP bytes")
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
            else:
                raise SmokeFailure("SSH local forwarding did not become ready")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        require(not thread.is_alive(), "HTTP fixture thread did not stop")


def exercise_git_and_tar(options, workspace, archive_contents):
    # Select private runtime executables explicitly: Debian already supplies tar,
    # so exercising only its PATH would not prove the bundled archive tool works.
    runtime = 'runtime_bin=$(dirname "$(readlink -f /usr/libexec/crabbox-sftp-server)")\n'
    identity = shlex.join([
        "env", "-i", "PATH=/usr/bin:/bin", "HOME=" + workspace,
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_TERMINAL_PROMPT=0", "LC_ALL=C",
    ])
    git_options = shlex.join([
        "-c", "user.name=Crabbox Runtime Smoke",
        "-c", "user.email=runtime-smoke@example.invalid",
        "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
        "-c", "commit.gpgSign=false", "-c", "http.sslVerify=true",
    ])
    git_function = f'git_smoke() {{ {identity} "$runtime_bin/git" {git_options} "$@"; }}\n'
    repo = shlex.quote(workspace + "/git-repository")
    committed = bytes(range(256)) * 5 + b"\x00committed-runtime-git-bytes\xff\n"
    command = "set -eu\n" + runtime + git_function + (
        f"mkdir -p {repo}\ncd {repo}\n"
        "git_smoke init -q -b main\n"
        "cat > tracked.bin\n"
        "git_smoke add -- tracked.bin\n"
        "git_smoke commit -q -m runtime-smoke\n"
        "printf '%s' modified-after-commit > tracked.bin\n"
        "git_smoke reset --hard -q HEAD\n"
        'test -z "$(git_smoke status --porcelain)"\n'
        "cat tracked.bin\n"
    )
    require(ssh_command(options, command, data=committed).stdout == committed, "bundled Git commit/reset did not restore exact file bytes")
    # This uses the actual packaged HTTPS helper and its CA configuration, with
    # no global Git config, credential helper, or disabled TLS verification.
    remote = ssh_command(
        options,
        "set -eu\n" + runtime + git_function + f"cd {shlex.quote(workspace)}\n"
        "git_smoke ls-remote https://github.com/git/git.git HEAD\n",
        timeout=120,
    )
    require(re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\tHEAD\n", remote.stdout) is not None, "bundled Git HTTPS helper did not return exactly HEAD and its object hash")

    command = "set -eu\n" + runtime + (
        f"cd {shlex.quote(workspace)}\n"
        "mkdir tar-extracted\n"
        'PATH="$runtime_bin:/usr/bin:/bin" "$runtime_bin/tar" -czf roundtrip.tar.gz sftp.bin\n'
        '"$runtime_bin/gzip" -t roundtrip.tar.gz\n'
        'PATH="$runtime_bin:/usr/bin:/bin" "$runtime_bin/tar" -xzf roundtrip.tar.gz -C tar-extracted\n'
        "cat tar-extracted/sftp.bin\n"
    )
    require(ssh_command(options, command).stdout == archive_contents, "bundled tar/gzip create/extract roundtrip changed bytes")


def exercise_ssh(options, foreign_key, workspace, local, image_path, image_env, image_command):
    require(ssh_command(options, "exit 37", check=False).returncode == 37, "SSH did not propagate remote exit 37")
    # Core manifest installation sends substantial shell programs in SSH exec
    # requests. Upstream Dropbear's 9000-byte string limit rejected these after
    # authentication; exercise a real larger request even without --crabbox.
    large_exec_value = "crabbox-large-exec:" + "x" * 16384
    large_exec = ssh_command(options, "printf '%s' " + shlex.quote(large_exec_value))
    require(large_exec.stdout == large_exec_value.encode(), "SSH exec request above 9000 bytes was truncated or corrupted")
    alien = list(options)
    alien[alien.index("-i") + 1] = str(foreign_key)
    denied = ssh_command(alien, "printf foreign-key-must-not-work", check=False)
    require(denied.returncode == 255 and b"Permission denied" in denied.stderr, failure_message("foreign-key authentication was not explicitly denied", denied.stderr))
    # Direct SSH command execution intentionally avoids a login shell: this is
    # the daemon's inherited image environment, not a shell profile's rewrite.
    preserved = ssh_command(
        options,
        'printf "%s\\n" "$PATH" "$CRABBOX_SMOKE_IMAGE_ENV"; '
        'command -v crabbox-image-marker; crabbox-image-marker',
    )
    expected_environment = f"{image_path}\n{image_env}\n{image_command}\nimage-path-preserved\n".encode()
    require(preserved.stdout == expected_environment, failure_message("SSH changed the image PATH/environment or lost its nonstandard image command", preserved.stderr, preserved.stdout))
    arguments = ["two words", "single'quote", "$HOME; $(false)", "line\nbreak", ""]
    expected = {"args": arguments, "env": "value with 'quotes' $dollars", "cwd": workspace}
    program = "import json,os,sys; print(json.dumps({'args':sys.argv[1:],'env':os.environ['SMOKE_VALUE'],'cwd':os.getcwd()}))"
    command = f"mkdir -p {shlex.quote(workspace)} && cd {shlex.quote(workspace)} && " + shlex.join(
        ["env", "SMOKE_VALUE=" + expected["env"], "bash", "-lc", 'exec "$@"', "bash", "python3", "-c", program, *arguments]
    )
    require(json.loads(ssh_command(options, command).stdout) == expected, "SSH argv, environment or working directory changed")
    pty_token = "crabbox-pty-input-" + uuid.uuid4().hex
    pty_marker = "crabbox-pty-roundtrip-" + uuid.uuid4().hex
    pty_script = 'test -t 0 && test -t 1 && IFS= read -r token && [ "$token" = ' + shlex.quote(pty_token) + " ] && printf '%s\\n' " + shlex.quote(pty_marker)
    pty_args = ["ssh", *options, "-tt", "root@127.0.0.1", pty_script]
    # Keep channel stdin open until the command exits: immediate EOF does not
    # model an interactive terminal and can race the remote PTY setup.
    with tempfile.TemporaryFile() as pty_stdout, tempfile.TemporaryFile() as pty_stderr:
        pty = subprocess.Popen(pty_args, stdin=subprocess.PIPE, stdout=pty_stdout, stderr=pty_stderr)
        try:
            try:
                pty.stdin.write((pty_token + "\n").encode())
                pty.stdin.flush()
                pty.wait(timeout=20)
            except (BrokenPipeError, subprocess.TimeoutExpired) as error:
                pty_stderr.seek(0)
                pty_stdout.seek(0)
                raise SmokeFailure(failure_message("PTY input roundtrip failed: " + shlex.join(pty_args), pty_stderr.read(), pty_stdout.read())) from error
            pty_stderr.seek(0)
            pty_stdout.seek(0)
            stdout, stderr = pty_stdout.read(), pty_stderr.read()
            require(pty.returncode == 0, failure_message("PTY command exited " + str(pty.returncode) + ": " + shlex.join(pty_args), stderr, stdout))
            lines = stdout.replace(b"\r\n", b"\n").splitlines()
            require(lines.count(pty_marker.encode()) == 1, failure_message("SSH PTY did not return its stdin-roundtrip marker", stderr, stdout))
        finally:
            with contextlib.suppress(BrokenPipeError):
                pty.stdin.close()
            if pty.poll() is None:
                pty.terminate()
                try:
                    pty.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pty.kill()
                    pty.wait(timeout=5)
            else:
                pty.wait()

    source, download = local / "rsync-source", local / "rsync-download"
    source.mkdir()
    download.mkdir()
    contents = {"ordinary.txt": b"real rsync\n", "spaces and 'quotes'.bin": bytes(range(256)) * 17}
    for name, content in contents.items():
        (source / name).write_bytes(content)
    remote_shell = shlex.join(["ssh", *options])
    remote = f"root@127.0.0.1:{workspace}/rsync/"
    run(["rsync", "-az", "--checksum", "-e", remote_shell, str(source) + "/", remote])
    run(["rsync", "-az", "--checksum", "-e", remote_shell, remote, str(download) + "/"])
    require({p.name: p.read_bytes() for p in download.iterdir()} == contents, "rsync upload/download byte mismatch")
    (source / "ordinary.txt").unlink()
    (source / "changed.txt").write_bytes(b"second synchronization\n")
    run(["rsync", "-az", "--checksum", "--delete", "-e", remote_shell, str(source) + "/", remote])
    run(["rsync", "-az", "--checksum", "--delete", "-e", remote_shell, remote, str(download) + "/"])
    require({p.name: p.read_bytes() for p in download.iterdir()} == {p.name: p.read_bytes() for p in source.iterdir()}, "rsync second sync/delete mismatch")

    upload = local / "sftp-upload.bin"
    retrieved = local / "sftp-download.bin"
    upload.write_bytes(bytes(range(256)) * 31 + b"\x00sftp-roundtrip\xff")
    # Private temporary paths are quoted for SFTP's own command parser.
    quote = lambda value: '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
    batch = f"put {quote(upload)} {quote(workspace + '/sftp.bin')}\nget {quote(workspace + '/sftp.bin')} {quote(retrieved)}\n"
    run(["sftp", *options, "-b", "-", "root@127.0.0.1"], data=batch.encode())
    require(retrieved.read_bytes() == upload.read_bytes(), "SFTP upload/download byte mismatch")
    exercise_git_and_tar(options, workspace, upload.read_bytes())
    forwarding_smoke(options)


def exercise_crabbox(binary, client, host_key, port, directory, token):
    try:
        _exercise_crabbox(binary, client, host_key, port, directory, token)
        from agent_sandbox_git_smoke import exercise_git_workflows
        from agent_sandbox_workflow_smoke import exercise_other_workflows

        runtime = sys.modules[__name__]
        exercise_git_workflows(runtime, binary, client, host_key, port, directory, token)
        exercise_other_workflows(runtime, binary, client, host_key, port, directory, token)
    except Exception as error:
        diagnostics = []
        for scope, bound in (("sync", 9000), ("workload", 262144)):
            log_path = directory / "core-cli" / ("ssh-command-lengths-" + scope)
            prefix = f"core CLI {scope} SSH exec lengths (bound={bound}): "
            try:
                lengths = [int(line) for line in log_path.read_text().splitlines()]
            except FileNotFoundError:
                diagnostic = prefix + "no observations recorded"
            except (OSError, ValueError) as log_error:
                diagnostic = prefix + "numeric log unavailable (" + type(log_error).__name__ + ")"
            else:
                diagnostic = (prefix + f"requests={len(lengths)}, "
                              f"exec_requests={sum(length > 0 for length in lengths)}, "
                              f"maximum_bytes={max(lengths, default=0)}, "
                              f"over_bound={sum(length > bound for length in lengths)}")
            diagnostics.append(diagnostic)
        raise SmokeFailure(str(error) + "\n" + "\n".join(diagnostics)) from error


def _exercise_crabbox(binary, client, host_key, port, directory, token):
    """Use the public static SSH provider against this initialized image only."""
    local = directory / "core-cli"
    local.mkdir(mode=0o700)
    repo = local / "cli-repo"
    repo.mkdir()
    environment = {"PATH": os.environ["PATH"], "LANG": "C", "LC_ALL": "C"}
    real_ssh = Path(shutil.which("ssh")).resolve()
    wrappers = local / "bin"
    wrappers.mkdir(mode=0o700)
    sync_lengths = local / "ssh-command-lengths-sync"
    workload_lengths = local / "ssh-command-lengths-workload"
    command_bound = local / "ssh-command-bound"
    command_bound.write_text("9000\n")
    observer = wrappers / "ssh-bound.py"
    observer.write_text(
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "index = 0\n"
        "while index < len(args) and args[index].startswith('-') and args[index] != '-':\n"
        "    option = args[index]\n"
        "    if option == '--':\n"
        "        index += 1\n"
        "        break\n"
        "    for position, flag in enumerate(option[1:], 1):\n"
        "        if flag in 'BbcDEeFIiJLlmOopQRSWw':\n"
        "            if position == len(option) - 1:\n"
        "                index += 1\n"
        "            break\n"
        "        if flag not in '1246AaCfGgKkMNnqsTtVvXxYy':\n"
        "            sys.stderr.write('SSH bound observer: unsupported option syntax\\n')\n"
        "            sys.exit(126)\n"
        "    index += 1\n"
        "command = args[index + 1:]\n"
        "length = sum(len(os.fsencode(part)) for part in command) + max(0, len(command) - 1)\n"
        f"with open({str(command_bound)!r}) as policy:\n"
        "    bound = int(policy.read())\n"
        f"log_path = {{9000: {str(sync_lengths)!r}, 262144: {str(workload_lengths)!r}}}[bound]\n"
        "fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
        "try:\n"
        "    os.write(fd, (str(length) + '\\n').encode('ascii'))\n"
        "finally:\n"
        "    os.close(fd)\n"
        "if length > bound:\n"
        "    sys.stderr.write(f'SSH exec command exceeds fixture bound: {length} > {bound} bytes\\n')\n"
        "    sys.exit(126)\n"
        f"os.execv({str(real_ssh)!r}, [{str(real_ssh)!r}, *args])\n"
    )
    wrapper = wrappers / "ssh"
    wrapper.write_text("#!/bin/sh\nexec " + shlex.join([sys.executable, str(observer)]) + ' "$@"\n')
    wrapper.chmod(0o700)
    # Observe only core CLI children, never the separate raw >16KiB regression.
    # Transport, stdin, authentication and argv pass to the real client intact.
    environment["PATH"] = str(wrappers) + os.pathsep + environment["PATH"]
    for variable, name in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                           ("XDG_STATE_HOME", "state"), ("XDG_CACHE_HOME", "cache"),
                           ("XDG_DATA_HOME", "data"), ("TMPDIR", "tmp")):
        path = local / name
        path.mkdir(mode=0o700)
        environment[variable] = str(path)
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                       GIT_TERMINAL_PROMPT="0", CRABBOX_SMOKE_CLI_VALUE="literal 'quotes' $HOME ;\nsecond line")
    credentials = local / "credentials"
    credentials.mkdir(mode=0o700)
    key = credentials / "identity"
    shutil.copyfile(client, key)
    key.chmod(0o600)
    # The supported ssh.key contract reads known_hosts from the key directory.
    # Preseeding the real endpoint pins it even with core's accept-new policy.
    known_hosts = credentials / "known_hosts"
    pinned_hosts = f"[127.0.0.1]:{port} {host_key}\n"
    known_hosts.write_text(pinned_hosts)
    known_hosts.chmod(0o600)
    lease = "static_smoke_" + token
    work_root = "/crabbox-smoke-" + token + "/core-work"
    workspace = work_root + "/" + lease + "/" + repo.name
    configuration = local / "config.json"
    configuration.write_text(json.dumps({
        "provider": "ssh", "target": "linux",
        "static": {"id": lease, "name": "runtime-smoke-" + token, "host": "127.0.0.1",
                   "user": "root", "port": str(port), "workRoot": work_root},
        "ssh": {"key": str(key), "fallbackPorts": []},
        "sync": {"gitSeed": False, "delete": True, "checksum": True},
    }))
    environment["CRABBOX_CONFIG"] = str(configuration)
    run(["git", "init", "-q", repo], env=environment)
    contents = bytes(range(256)) * 19 + b"\x00core-cli-roundtrip\xff"
    source = repo / "spaces and 'quotes'.bin"
    source.write_bytes(contents)
    (repo / "removed.txt").write_bytes(b"remove on second sync\n")
    (repo / "probe.py").write_text(
        "import hashlib, json, os, pathlib, sys\n"
        "payload = pathlib.Path(\"spaces and 'quotes'.bin\").read_bytes()\n"
        "pathlib.Path('roundtrip.bin').write_bytes(payload)\n"
        "print(json.dumps({'cwd': os.getcwd(), 'env': os.environ['CRABBOX_SMOKE_CLI_VALUE'], "
        "'argv': sys.argv[1:], 'sha256': hashlib.sha256(payload).hexdigest(), "
        "'removed_exists': pathlib.Path('removed.txt').exists()}, sort_keys=True))\n"
    )
    run(["git", "add", "--", "."], cwd=repo, env=environment)
    run(["git", "-c", "user.name=Runtime Smoke", "-c", "user.email=runtime-smoke@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-qm", "runtime fixture"], cwd=repo, env=environment)
    common = [binary, "run", "--provider", "ssh", "--target", "linux",
              "--static-host", "127.0.0.1", "--keep", "--no-hydrate", "--timing-record", "off"]
    literal = ["", "space value", "'single' and \"double\"", "$HOME; $(printf unsafe)", "line one\nline two", "*"]
    for phase in ("initial", "reused-sync"):
        if phase == "reused-sync":
            contents = contents[::-1]
            source.write_bytes(contents)
            (repo / "removed.txt").unlink()
        capture = local / (phase + ".stdout")
        downloaded = local / (phase + ".bin")
        reuse = ["--id", lease] if phase == "reused-sync" else []
        # The legacy command bound applies to generated synchronization only.
        # Unchanged user-command/owner wrappers use the bundle's normal bound.
        command_bound.write_text("9000\n")
        run([*common, *reuse, "--sync-only"], cwd=repo, env=environment, timeout=300)
        observed_sync = [int(line) for line in sync_lengths.read_text().splitlines()]
        require(observed_sync and 0 < max(observed_sync) <= 9000,
                "core CLI sync did not exercise observed SSH exec requests within the original 9000-byte bound")
        command_bound.write_text("262144\n")
        command = [*common, "--id", lease, "--no-sync", "--allow-env", "CRABBOX_SMOKE_CLI_VALUE",
                   "--capture-stdout", capture, "--download", "roundtrip.bin=" + str(downloaded),
                   "--", "python3", "probe.py", phase, *literal]
        run(command, cwd=repo, env=environment, timeout=300)
        expected = {"cwd": workspace, "env": environment["CRABBOX_SMOKE_CLI_VALUE"],
                    "argv": [phase, *literal], "sha256": hashlib.sha256(contents).hexdigest(),
                    "removed_exists": phase == "initial"}
        require(capture.read_bytes() == (json.dumps(expected, sort_keys=True) + "\n").encode(),
                failure_message("core CLI literal argv/env/cwd or synchronization mismatch", b"", capture.read_bytes()))
        require(downloaded.read_bytes() == contents, "core CLI --download byte mismatch")
        require(known_hosts.read_text() == pinned_hosts, "core CLI changed the preseeded endpoint host key")
    result = run([*common, "--id", lease, "--no-sync", "--", "python3", "-c", "raise SystemExit(37)"],
                 cwd=repo, env=environment, timeout=180, check=False)
    require(result.returncode == 37, failure_message(f"core CLI reused command returned {result.returncode}, expected 37", result.stderr, result.stdout))
    observed_workload = [int(line) for line in workload_lengths.read_text().splitlines()]
    require(observed_workload and 0 < max(observed_workload) <= 262144,
            "core CLI workload did not exercise observed SSH exec requests within the bundled 256KiB bound")
    print(f"PASS core CLI provider=ssh against initialized Debian: --sync-only initial and changed/deleted resync SSH exec <=9000 bytes (maximum {max(observed_sync)}); --id --no-sync literal argv/env/cwd, exact-byte --download and exit 37 SSH exec <=262144 bytes (maximum {max(observed_workload)}) (not a Kubernetes-provider proof)", flush=True)


def configure_shells_fixture(container, mode):
    """Change only this disposable image, before its preservation baseline."""
    root = docker("exec", container, "/bin/sh", "-c",
                  'while IFS=: read -r name password uid gid gecos home shell; do '
                  '[ "$name" != root ] || { printf "%s:%s\\n" "$uid" "$shell"; break; }; '
                  'done </etc/passwd').stdout
    require(root == b"0:/bin/bash\n", "shell-independence Debian fixture requires existing root UID 0 with /bin/bash")
    docker("exec", container, "/bin/sh", "-c", "test -x /bin/bash")
    if mode == "absent":
        docker("exec", container, "rm", "-f", "/etc/shells")
    else:
        require(mode == "nonmatching", "unknown shells fixture mode")
        docker("exec", container, "/bin/sh", "-c", "printf '%s\\n' /bin/sh > /etc/shells")


def image_smoke(image, reject, initializer, payload, directory, crabbox=None, shells_fixture=None):
    token = uuid.uuid4().hex
    lease = "smoke_" + token
    alias = "runtime-" + token
    fixture_path = "/crabbox-smoke-" + token
    image_bin = fixture_path + "/image-bin"
    image_path = image_bin + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    image_env = "image-environment-" + token
    container = None
    client, public = key_pair(directory, "lease-client")
    foreign, _ = key_pair(directory, "foreign-client")
    fixture = directory / "fixture"
    fixture.mkdir(mode=0o700)
    (fixture / "image-bin").mkdir(mode=0o755)
    image_command = fixture / "image-bin/crabbox-image-marker"
    image_command.write_text("#!/bin/sh\nprintf '%s\\n' image-path-preserved\n")
    image_command.chmod(0o755)
    extract_fixture_tools(payload, fixture)
    (fixture / "authorized_keys").write_text(public + "\n")
    (fixture / "authorized_keys").chmod(0o600)
    shutil.copyfile(initializer, fixture / "initialize")
    (fixture / "initialize").chmod(0o700)
    known_hosts = directory / "known_hosts"
    try:
        # Fail rather than disturb an existing host-network listener on 2222.
        with socket.socket() as check_port:
            try:
                check_port.bind(("127.0.0.1", 2222))
            except OSError as error:
                raise SmokeFailure("runner loopback port 2222 is already occupied; no process was modified") from error
        # A private root-level fixture keeps Dropbear's authorized_keys ancestors
        # trusted without changing the image's /tmp or adding a mount.
        result = docker("create", "--network=host", "--name", "crabbox-runtime-smoke-" + token,
                        "--label", "crabbox.runtime-smoke=" + token,
                        "--env", "PATH=" + image_path, "--env", "CRABBOX_SMOKE_IMAGE_ENV=" + image_env,
                        "--entrypoint", "/bin/sh", image,
                        "-c", "while :; do sleep 3600; done", timeout=240)
        container = result.stdout.decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", container) is not None, "docker create did not return a container ID")
        docker("start", container)
        if shells_fixture is not None:
            configure_shells_fixture(container, shells_fixture)
        docker("cp", str(fixture), f"{container}:{fixture_path}")
        docker("exec", container, fixture_path + "/dropbearkey", "-t", "ed25519", "-f", fixture_path + "/hostkey")
        key_output = docker("exec", container, fixture_path + "/dropbearkey", "-y", "-f", fixture_path + "/hostkey").stdout.decode()
        keys = [canonical_key(line) for line in key_output.splitlines() if line.startswith("ssh-ed25519 ")]
        require(len(keys) == 1, "unrelated SSH fixture did not generate exactly one host key")
        known_hosts.write_text("unrelated-" + alias + " " + keys[0] + "\n")
        known_hosts.chmod(0o600)
        daemon_args = [fixture_path + "/dropbear", "-F", "-e", "-s", "-m",
                       "-D", fixture_path, "-r", fixture_path + "/hostkey", "-P", fixture_path + "/unrelated.pid",
                       "-p", "127.0.0.1:2222"]
        daemon_start = "exec " + shlex.join(daemon_args) + " </dev/null >>" + shlex.quote(fixture_path + "/unrelated.log") + " 2>&1"
        docker("exec", "-d", container, "/bin/sh", "-c", daemon_start)
        unrelated = ssh_options(client, known_hosts, "unrelated-" + alias, 2222)
        wait_ssh(unrelated, "unrelated-before")
        before = snapshot(container)
        request = {"lease_id": lease, "public_key": public}
        result = docker("exec", "-i", container, fixture_path + "/initialize", data=json.dumps(request).encode(), timeout=240, check=False)
        assert_unchanged(before, snapshot(container))
        if reject:
            diagnostic = result.stderr.decode("utf-8", "replace").lower()
            require(result.returncode != 0, "raw Alpine unexpectedly accepted incompatible existing tools")
            require(("flock" in diagnostic or "ps" in diagnostic) and ("required behavior" in diagnostic or "support" in diagnostic), failure_message("raw Alpine was not rejected for existing ps/flock incompatibility", result.stderr))
            require(b"CRABBOX_SSH_" not in result.stdout, "rejected initialization published an SSH endpoint")
            wait_ssh(unrelated, "unrelated-after-rejection")
            print("PASS raw Alpine: incompatible existing tools rejected; original tools/accounts and unrelated SSH preserved", flush=True)
            return
        require(result.returncode == 0, failure_message(f"{image}: initializer failed (exit {result.returncode}); command: " + shlex.join(["docker", "exec", "-i", container, fixture_path + "/initialize"]), result.stderr, result.stdout))
        host_key, port = parse_endpoint(result.stdout)
        require(port != 2222, "initializer reused unrelated SSH port 2222")
        with known_hosts.open("a") as output:
            output.write(alias + " " + host_key + "\n")
        options = ssh_options(client, known_hosts, alias, port)
        wait_ssh(options, "lease-authenticated")
        if shells_fixture is None:
            exercise_ssh(options, foreign, "/tmp/crabbox-work-" + token, directory,
                         image_path, image_env, image_bin + "/crabbox-image-marker")
            print("PASS Debian: pinned key-only SSH, foreign-key rejection, exit status, >16KiB exec request, argv/env, PTY, rsync, SFTP, Git commit/reset/HTTPS, tar/gzip and TCP forwarding", flush=True)
            if crabbox is not None:
                exercise_crabbox(crabbox, client, host_key, port, directory, token)
        else:
            identity = ssh_command(options, 'printf "%s\\n" "$SHELL"; id -u')
            require(identity.stdout == b"/bin/bash\n0\n", "shell-independence SSH did not retain the existing root account and Bash shell")
        repeated = docker("exec", "-i", container, fixture_path + "/initialize", data=json.dumps(request).encode(), timeout=240)
        require(parse_endpoint(repeated.stdout) == (host_key, port), "reinitialization changed the healthy endpoint")
        wait_ssh(options, "lease-reused")
        wait_ssh(unrelated, "unrelated-after-reuse")
        if shells_fixture is None:
            state = "/var/lib/crabbox-ssh/" + lease
            pid_before = docker("exec", container, "/bin/cat", state + "/dropbear.pid").stdout
            docker("exec", container, "/bin/mv", state + "/port", state + "/port.saved")
            ambiguous = docker("exec", "-i", container, fixture_path + "/initialize",
                               data=json.dumps(request).encode(), timeout=240, check=False)
            require(ambiguous.returncode != 0 and b"CRABBOX_SSH_" not in ambiguous.stdout,
                    "initializer published an endpoint while a daemon had lost its port state")
            require(docker("exec", container, "/bin/cat", state + "/dropbear.pid").stdout == pid_before,
                    "missing port state replaced the live daemon PID")
            wait_ssh(options, "lease-preserved-without-port-state")
            wait_ssh(unrelated, "unrelated-preserved-without-port-state")
            docker("exec", container, "/bin/mv", state + "/port.saved", state + "/port")

            # Restart only this owned fixture container, then discard the old
            # ephemeral key/listener state. No old process survives the restart.
            docker("restart", container, timeout=60)
            docker("exec", "-d", container, "/bin/sh", "-c", daemon_start)
            wait_ssh(unrelated, "unrelated-after-container-restart")
            docker("exec", container, "/bin/rm", "-f", state + "/host_ed25519", state + "/port", state + "/dropbear.pid")
            recovered = docker("exec", "-i", container, fixture_path + "/initialize",
                               data=json.dumps(request).encode(), timeout=240)
            recovered_key, recovered_port = parse_endpoint(recovered.stdout)
            require(recovered_key != host_key, "missing host private key was not regenerated")
            require(recovered_port != 2222, "recovery commandeered the unrelated SSH listener")
            recovered_alias = alias + "-recovered"
            with known_hosts.open("a") as output:
                output.write(recovered_alias + " " + recovered_key + "\n")
            recovered_options = ssh_options(client, known_hosts, recovered_alias, recovered_port)
            wait_ssh(recovered_options, "lease-recovered-from-missing-state")
            reused = docker("exec", "-i", container, fixture_path + "/initialize",
                            data=json.dumps(request).encode(), timeout=240)
            require(parse_endpoint(reused.stdout) == (recovered_key, recovered_port),
                    "reinitialization changed the recovered endpoint")
            wait_ssh(unrelated, "unrelated-after-state-recovery")
            print("PASS Debian: ambiguous live-daemon recovery rejected without replacement; missing ephemeral state re-bootstrapped after container restart", flush=True)
        assert_unchanged(before, snapshot(container))
        label = "Debian" if shells_fixture is None else "Debian /etc/shells " + shells_fixture + ": existing root /bin/bash key authentication"
        print(f"PASS {label}: endpoint reuse, original tools/accounts unchanged, unrelated SSH still accessible", flush=True)
    except Exception as error:
        if container is not None and re.fullmatch(r"[0-9a-f]{64}", container):
            details = []
            for label, path in (("unrelated", fixture_path + "/unrelated.log"),
                                ("initializer", "/var/lib/crabbox-ssh/" + lease + "/dropbear.log")):
                try:
                    log = docker("exec", container, "/bin/sh", "-c", 'if [ -f "$1" ]; then cat "$1"; fi', "sh", path, timeout=10, check=False)
                except (SmokeFailure, OSError, subprocess.SubprocessError) as log_error:
                    details.append(f"could not collect {label} daemon log: {log_error}")
                    continue
                detail = diagnostic_tail(log.stdout)
                if detail:
                    details.append(label + " daemon log:\n" + detail)
                elif log.returncode:
                    details.append(failure_message(f"could not collect {label} daemon log (exit {log.returncode})", log.stderr))
            if details:
                raise SmokeFailure(str(error) + "\n" + "\n".join(details)) from error
        raise
    finally:
        # The fixture daemon and initializer daemon belong to this container.
        # Never use process-name killing or Docker prune/global cleanup.
        if container is not None and re.fullmatch(r"[0-9a-f]{64}", container):
            docker("rm", "-f", container, timeout=60)


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initializer", type=Path, default=root / "internal/providers/agentsandbox/assets/initializer-linux-amd64.gz", help="generated native Linux amd64 initializer gzip")
    parser.add_argument("--payload", type=Path, default=root / "runtimes/agent-sandbox/payload.tar.gz", help="matching native payload archive (for unrelated real daemon fixture)")
    parser.add_argument("--crabbox", type=Path, help="optional built CLI: exercise core run/sync/download via provider=ssh against initialized Debian")
    parser.add_argument("--debian-image", default="debian:bookworm-slim")
    parser.add_argument("--alpine-image", default="alpine:3.22")
    args = parser.parse_args()
    for binary in ("docker", "ssh", "ssh-keygen", "sftp", "rsync"):
        require(shutil.which(binary) is not None, f"required runner executable missing: {binary}")
    if args.crabbox is not None:
        args.crabbox = args.crabbox.resolve()
        require(args.crabbox.is_file() and os.access(args.crabbox, os.X_OK), "--crabbox must name an existing executable CLI")
        require(shutil.which("git") is not None, "core CLI smoke requires local git")
    require(sys.platform == "linux" and os.uname().machine in ("x86_64", "amd64"), "this smoke harness requires native Linux amd64")
    require(args.initializer.is_file() and args.payload.is_file(), "generate matching initializer and native payload assets first")
    docker("info", "--format", "{{.ServerVersion}}", timeout=30)
    with tempfile.TemporaryDirectory(prefix="crabbox-runtime-smoke-") as temporary:
        directory = Path(temporary)
        initializer = directory / "initialize"
        with gzip.open(args.initializer, "rb") as source, initializer.open("wb") as output:
            shutil.copyfileobj(source, output)
        initializer.chmod(0o700)
        cases = (("debian", args.debian_image, False, None),
                 ("debian-shells-absent", args.debian_image, False, "absent"),
                 ("debian-shells-nonmatching", args.debian_image, False, "nonmatching"),
                 ("alpine", args.alpine_image, True, None))
        for name, image, reject, shells_fixture in cases:
            case_directory = directory / name
            case_directory.mkdir(mode=0o700)
            image_smoke(image, reject, initializer, args.payload, case_directory, args.crabbox, shells_fixture)
    print("PASS all runtime image smoke scenarios; owned containers and fixture processes cleaned", flush=True)


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print("FAIL runtime smoke: interrupted; owned-resource cleanup attempted", file=sys.stderr)
        sys.exit(130)
    except (SmokeFailure, OSError, tarfile.TarError) as error:
        print(f"FAIL runtime smoke: {error}", file=sys.stderr)
        sys.exit(1)

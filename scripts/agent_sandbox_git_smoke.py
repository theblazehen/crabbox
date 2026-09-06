"""Real Git/HTTP and public CLI smoke against the bundled Debian SSH daemon."""

import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import threading
import urllib.parse


@contextlib.contextmanager
def _git_http(runtime, root, environment):
    backend = Path(runtime.run(["git", "--exec-path"], env=environment).stdout.decode().strip()) / "git-http-backend"
    runtime.require(backend.is_file() and os.access(backend, os.X_OK),
                    "real git-http-backend is required for the Git workflow smoke")
    requests = []
    errors = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            pass

        def serve_git(self):
            parsed = urllib.parse.urlsplit(self.path)
            requests.append((self.command, parsed.path))
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 8 * 1024 * 1024:
                    raise ValueError("unexpected Git request size")
                env = dict(environment, GIT_PROJECT_ROOT=str(root), GIT_HTTP_EXPORT_ALL="1",
                           REQUEST_METHOD=self.command, PATH_INFO=parsed.path,
                           QUERY_STRING=parsed.query, CONTENT_TYPE=self.headers.get("Content-Type", ""),
                           CONTENT_LENGTH=str(length), SERVER_PROTOCOL="HTTP/1.1",
                           REMOTE_ADDR=self.client_address[0])
                if self.headers.get("Git-Protocol"):
                    env["HTTP_GIT_PROTOCOL"] = self.headers["Git-Protocol"]
                result = subprocess.run([str(backend)], input=self.rfile.read(length),
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env=env, timeout=45, check=False)
                if result.returncode:
                    raise RuntimeError(runtime.failure_message("git-http-backend failed", result.stderr))
                headers, separator, body = result.stdout.partition(b"\r\n\r\n")
                if not separator:
                    raise ValueError("git-http-backend returned no CGI headers")
                fields = [line.decode("latin-1").split(":", 1) for line in headers.split(b"\r\n")]
                status = next((int(value.strip().split()[0]) for key, value in fields if key.lower() == "status"), 200)
                self.send_response(status)
                for key, value in fields:
                    if key.lower() not in ("status", "content-length", "connection"):
                        self.send_header(key, value.strip())
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as error:
                errors.append(str(error))
                self.send_error(500, "Git fixture backend failed")

        do_GET = serve_git
        do_POST = serve_git

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever, name="git-smoke-http")
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/repo.git", requests, errors
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        runtime.require(not thread.is_alive(), "Git HTTP fixture did not stop")


def exercise_git_workflows(runtime, binary, client, host_key, port, directory, token):
    """Exercise successful seed, overlay, reuse, fetch and reseed via real SSH."""
    local = Path(directory) / "git-workflows"
    local.mkdir(mode=0o700)
    environment = {"PATH": os.environ["PATH"], "LANG": "C", "LC_ALL": "C",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0"}
    for variable in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR"):
        path = local / variable.lower()
        path.mkdir(mode=0o700)
        environment[variable] = str(path)
    credentials = local / "credentials"
    credentials.mkdir(mode=0o700)
    key = credentials / "identity"
    shutil.copyfile(client, key)
    key.chmod(0o600)
    known_hosts = credentials / "known_hosts"
    pinned_hosts = f"[127.0.0.1]:{port} {host_key}\ngit-smoke-{token} {host_key}\n"
    known_hosts.write_text(pinned_hosts)
    known_hosts.chmod(0o600)
    options = runtime.ssh_options(key, known_hosts, "git-smoke-" + token, port)
    origin_root = local / "origins"
    origin_root.mkdir()
    origin = origin_root / "repo.git"
    publisher = local / "publisher"

    def git(*args, cwd=None):
        return runtime.run(["git", *args], cwd=cwd, env=environment).stdout.decode().strip()

    git("init", "--bare", "--initial-branch=main", str(origin))
    git("-C", str(origin), "config", "uploadpack.allowFilter", "true")
    git("init", "--initial-branch=main", str(publisher))
    for name, value in (("user.name", "Crabbox Git Smoke"), ("user.email", "git-smoke@example.invalid"),
                        ("commit.gpgsign", "false"), ("core.autocrlf", "false")):
        git("config", name, value, cwd=publisher)
    (publisher / "tracked.txt").write_bytes(b"initial tracked content\n")
    (publisher / "removed.txt").write_bytes(b"remove in dirty overlay\n")
    (publisher / "executable.sh").write_bytes(b"#!/bin/sh\nprintf 'git-smoke-executable\\n'\n")
    (publisher / "executable.sh").chmod(0o755)
    (publisher / "link").symlink_to("tracked.txt")
    git("add", ".", cwd=publisher)
    git("commit", "-qm", "initial fixture", cwd=publisher)
    git("remote", "add", "origin", str(origin), cwd=publisher)
    git("push", "-qu", "origin", "main", cwd=publisher)
    paths = ["tracked.txt", "removed.txt", "executable.sh", "link", "new 'untracked'.bin", "revision.txt"]
    work_root = "/crabbox-smoke-" + token + "/git-work"
    cleanup = []

    def snapshot_source(repo):
        files = {}
        for name in paths:
            path = repo / name
            if path.is_symlink():
                files[name] = {"link": os.readlink(path)}
            elif path.is_file():
                files[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                               "executable": bool(path.stat().st_mode & 0o111)}
        return {"files": files, "head": git("rev-parse", "HEAD", cwd=repo),
                "tree": git("write-tree", cwd=repo),
                "status": git("status", "--porcelain=v1", "--untracked-files=all", "--", *paths, cwd=repo)}

    def verify_remote(repo, workspace, url):
        script = (
            "import hashlib,json,os,pathlib,subprocess\n"
            f"os.chdir({workspace!r})\n"
            "def git(*args):\n"
            " return subprocess.check_output(['git',*args]).decode().strip()\n"
            "files={}\n"
            f"for name in {paths!r}:\n"
            " p=pathlib.Path(name)\n"
            " if p.is_symlink(): files[name]={'link':os.readlink(p)}\n"
            " elif p.is_file(): files[name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'executable':bool(p.stat().st_mode & 0o111)}\n"
            "meta=pathlib.Path('.git/crabbox')\n"
            "metadata={name:(meta/name).read_text() if (meta/name).is_file() else '' for name in ['sync-fingerprint','sync-finalize-token','sync-finalize-complete-token']}\n"
            f"print(json.dumps(dict(files=files,head=git('rev-parse','HEAD'),tree=git('write-tree'),status=git('status','--porcelain=v1','--untracked-files=all','--',*{paths!r}),origin=git('remote','get-url','origin'),metadata=metadata)))\n"
        )
        state = json.loads(runtime.ssh_command(options, shlex.join(["python3", "-c", script])).stdout)
        expected = snapshot_source(repo)
        runtime.require({key: state[key] for key in expected} == expected,
                        "Git remote content/type/mode/HEAD/index/status mismatch: " + json.dumps({"expected": expected, "actual": state}, sort_keys=True))
        runtime.require(state["origin"] == url, "remote Git origin differs from real HTTP fixture")
        meta = state["metadata"]
        runtime.require(meta["sync-fingerprint"] and meta["sync-finalize-token"] and
                        meta["sync-finalize-token"] == meta["sync-finalize-complete-token"],
                        "remote Git sync metadata was not fully finalized")
        runtime.require(known_hosts.read_text() == pinned_hosts, "Git workflow changed pinned SSH host identity")
        return state

    with _git_http(runtime, origin_root, environment) as (url, requests, errors):
        try:
            for overlay in (False, True):
                lane = "overlay" if overlay else "seed"
                checkout_parent = local / lane
                checkout_parent.mkdir()
                repo = checkout_parent / "repo"
                git("clone", "--quiet", url, str(repo))
                git("config", "core.autocrlf", "false", cwd=repo)
                lease = "static_git_" + lane + "_" + token
                workspace = work_root + "/" + lease + "/repo"
                configuration = checkout_parent / "config.json"
                configuration.write_text(json.dumps({
                    "provider": "ssh", "target": "linux",
                    "static": {"id": lease, "name": "git-" + lane + "-" + token,
                               "host": "127.0.0.1", "user": "root", "port": str(port), "workRoot": work_root},
                    "ssh": {"key": str(key), "fallbackPorts": []},
                    "sync": {"gitSeed": True, "gitOverlay": overlay, "fingerprint": True,
                             "baseRef": "main", "delete": True, "checksum": True},
                }))
                lane_env = dict(environment, CRABBOX_CONFIG=str(configuration))
                common = [binary, "run", "--provider", "ssh", "--target", "linux", "--static-host", "127.0.0.1",
                          "--keep", "--no-hydrate", "--timing-record", "off", "--timing-json"]
                cleanup.append((lease, repo, lane_env))

                def sync(phase, *, first=False, full=False):
                    result = runtime.run([*common, *([] if first else ["--id", lease]),
                                          *(["--full-resync"] if full else []), "--sync-only"],
                                         cwd=repo, env=lane_env, timeout=300)
                    (checkout_parent / (phase + ".stdout")).write_bytes(result.stdout)
                    (checkout_parent / (phase + ".stderr")).write_bytes(result.stderr)
                    log = (result.stdout + result.stderr).decode(errors="replace")
                    reports = []
                    for line in log.splitlines():
                        try:
                            report = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(report, dict) and report.get("leaseId") == lease and "syncSkipped" in report:
                            reports.append(report)
                    runtime.require(reports, runtime.failure_message("Git smoke received no timing JSON", result.stderr, result.stdout))
                    report = reports[-1]
                    runtime.require(not errors, "Git HTTP fixture errors: " + "; ".join(errors))
                    runtime.require("remote git seed failed" not in log and "git origin fallback" not in log,
                                    runtime.failure_message("Git smoke silently fell back from real origin", result.stderr, result.stdout))
                    if overlay:
                        if full:
                            runtime.require(report.get("syncFallbackReason") == "full_resync" and report.get("syncMode") == "manifest",
                                            "full resync did not explicitly choose normal manifest reseeding")
                        else:
                            runtime.require(report.get("syncMode") == "git-overlay" and not report.get("syncFallbackReason") and "git overlay fallback" not in log,
                                            runtime.failure_message("requested Git overlay did not execute", result.stderr, result.stdout))
                    else:
                        runtime.require(not report.get("syncFallbackReason") and "git overlay fallback" not in log,
                                        "ordinary Git seed unexpectedly fell back")
                    if full:
                        runtime.require("full-resync resetting remote workdir" in log, "full-resync did not reset remote checkout")
                    return report

                before = len(requests)
                sync("initial", first=True)
                state = verify_remote(repo, workspace, url)
                runtime.require(len(requests) > before, "initial Git seed made no real HTTP request")
                print(f"PASS Git {lane}: real smart-HTTP seed, matching origin/HEAD/index/content/status and finalized fingerprint", flush=True)
                before = len(requests)
                repeat = sync("unchanged")
                repeated = verify_remote(repo, workspace, url)
                runtime.require(repeated["metadata"]["sync-fingerprint"] == state["metadata"]["sync-fingerprint"], "unchanged fingerprint changed")
                runtime.require(len(requests) == before, "unchanged Git checkout fetched instead of reusing its fingerprint")
                runtime.require(repeat.get("syncTransferFiles", 0) == 0 if overlay else repeat["syncSkipped"],
                                "unchanged Git reuse unexpectedly transferred source files")
                print(f"PASS Git {lane}: unchanged fingerprint reuse without HTTP fetch" + (" or source overlay payload" if overlay else " (sync skipped)"), flush=True)
                if overlay:
                    (repo / "tracked.txt").write_bytes(b"dirty tracked bytes\x00\xff\n")
                    (repo / "removed.txt").unlink()
                    (repo / "new 'untracked'.bin").write_bytes(bytes(range(256)) * 3)
                    (repo / "executable.sh").chmod(0o644)
                    (repo / "link").unlink()
                    (repo / "link").symlink_to("new 'untracked'.bin")
                    dirty = sync("dirty")
                    verify_remote(repo, workspace, url)
                    runtime.require(dirty.get("syncTransferFiles", 0) > 0, "dirty Git overlay transferred no changed files")
                    print("PASS Git overlay: dirty tracked/untracked/deleted paths, executable-bit change, symlink target and exact binary bytes/status", flush=True)
                    git("reset", "--hard", "HEAD", cwd=repo)
                    (repo / "new 'untracked'.bin").unlink()
                (publisher / "revision.txt").write_text("committed revision for " + lane + "\n")
                git("add", "revision.txt", cwd=publisher)
                git("commit", "-qm", "advance " + lane, cwd=publisher)
                git("push", "-q", "origin", "main", cwd=publisher)
                git("pull", "--quiet", "--ff-only", cwd=repo)
                before = len(requests)
                sync("next-commit")
                verify_remote(repo, workspace, url)
                runtime.require(len(requests) > before, "new committed revision reached target without a real HTTP fetch")
                print(f"PASS Git {lane}: next committed revision fetched over HTTP and HEAD/index/content advanced", flush=True)
                marker = workspace + "/.git/smoke-reseed-sentinel"
                runtime.ssh_command(options, "printf owned > " + shlex.quote(marker))
                before = len(requests)
                sync("full-resync", full=True)
                verify_remote(repo, workspace, url)
                runtime.require(len(requests) > before, "full-resync did not reseed over HTTP")
                runtime.ssh_command(options, "test ! -e " + shlex.quote(marker))
                print(f"PASS Git {lane}: full-resync removed old Git metadata and reseeded matching HEAD/content over HTTP", flush=True)
        finally:
            cleanup_errors = []
            for lease, repo, lane_env in reversed(cleanup):
                try:
                    result = runtime.run([binary, "stop", "--provider", "ssh", lease], cwd=repo,
                                         env=lane_env, timeout=90, check=False)
                    if result.returncode:
                        cleanup_errors.append(runtime.failure_message("Git lease cleanup failed: " + lease, result.stderr, result.stdout))
                except Exception as error:
                    cleanup_errors.append(str(error))
            try:
                runtime.ssh_command(options, "rm -rf -- " + shlex.quote(work_root), timeout=30)
            except Exception as error:
                cleanup_errors.append(str(error))
            runtime.require(not cleanup_errors, "\n".join(cleanup_errors))
    print("PASS Git workflows: real HTTP backend stopped; owned static leases and remote workspaces cleaned (Debian bundled SSH, not Kubernetes-provider proof)", flush=True)

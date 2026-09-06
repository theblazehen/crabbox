"""Real CLI workflow probes for an already initialized bundled SSH daemon."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile


def exercise_other_workflows(runtime, binary, client, host_key, port, directory, token):
    """Exercise public static-SSH sync, scripts, captures and local Actions APIs."""
    require = runtime.require
    local = Path(directory) / "other-workflows"
    local.mkdir(mode=0o700)
    repo = local / "workflow-repo"
    repo.mkdir()
    environment = {"PATH": os.environ["PATH"], "LANG": "C", "LC_ALL": "C",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0"}
    for variable in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
                     "XDG_DATA_HOME", "TMPDIR"):
        path = local / variable.lower()
        path.mkdir(mode=0o700)
        environment[variable] = str(path)
    credentials = local / "credentials"
    credentials.mkdir(mode=0o700)
    key = credentials / "identity"
    shutil.copyfile(client, key)
    key.chmod(0o600)
    pinned = f"[127.0.0.1]:{port} {host_key}\n"
    known_hosts = credentials / "known_hosts"
    known_hosts.write_text(pinned)
    known_hosts.chmod(0o600)
    alias = "workflow-smoke-" + token
    inspection_hosts = credentials / "inspection_hosts"
    inspection_hosts.write_text(f"{alias} {host_key}\n")
    inspection_hosts.chmod(0o600)
    options = runtime.ssh_options(key, inspection_hosts, alias, port)
    lease = "static_workflow_" + token
    work_root = "/crabbox-smoke-" + token + "/other-work"
    workspace = work_root + "/" + lease + "/" + repo.name
    owner_key = hashlib.sha256(("crabbox-workspace-owner-v1\0" + lease).encode()).hexdigest()
    configuration = local / "config.json"
    configuration.write_text(json.dumps({
        "provider": "ssh", "target": "linux",
        "static": {"id": lease, "name": alias, "host": "127.0.0.1", "user": "root",
                   "port": str(port), "workRoot": work_root},
        "ssh": {"key": str(key), "fallbackPorts": []},
        "sync": {"gitSeed": True, "gitOverlay": False, "fingerprint": True,
                 "baseRef": "main", "delete": True, "checksum": True},
    }))
    environment["CRABBOX_CONFIG"] = str(configuration)

    def invoke(args, *, data=None, check=True):
        return runtime.run([binary, *args], cwd=repo, env=environment, data=data,
                           check=check, timeout=300)

    def remote_python(source, *args):
        return runtime.ssh_command(options, shlex.join(["python3", "-c", source, *args]))

    def remote_state():
        result = remote_python(
            "import json,pathlib,sys\n"
            "root=pathlib.Path.home()/'.crabbox/workspace-owners'\n"
            "key=sys.argv[1]\n"
            "active=[p.name for p in root.glob(key+'*') if p.name in "
            "(key+'.owner',key+'.child') or p.name.startswith((key+'.run.',key+'.launcher.'))]\n"
            "print(json.dumps({'active':sorted(active),'staging':sorted(str(p) for p in "
            "pathlib.Path('/tmp').glob('crabbox-sync-script-*'))}))\n", owner_key)
        return json.loads(result.stdout)

    baseline = remote_state()
    require(not baseline["active"], "workflow fixture lease already has active ownership state")

    def assert_released(phase):
        state = remote_state()
        require(not state["active"], f"{phase}: owner/child/launcher state retained: {state['active']}")
        require(state["staging"] == baseline["staging"],
                f"{phase}: uploaded sync staging was not cleaned: {state['staging']}")
        require(known_hosts.read_text() == pinned, f"{phase}: pinned host key changed")

    common = ["run", "--provider", "ssh", "--target", "linux", "--static-host", "127.0.0.1",
              "--keep", "--no-hydrate", "--timing-record", "off"]
    reused = [*common, "--id", lease]
    literal = ["", "space value", "'single' and \"double\"", "$HOME; $(printf unsafe)",
               "first line\nsecond line", "*"]
    original = bytes(range(256)) * 11 + b"\0workflow-payload\xff\n"
    payload = original[::-1]
    source = repo / "payload 'quoted'.bin"
    source.write_bytes(original)
    (repo / "removed.txt").write_text("remove this on changed sync\n")
    (repo / "hydration-input.txt").write_text("hydration-first\n")
    (repo / "probe.py").write_text(
        "import hashlib,json,os,pathlib,sys\n"
        "p=pathlib.Path(\"payload 'quoted'.bin\").read_bytes()\n"
        "print(json.dumps({'phase':sys.argv[1],'sha256':hashlib.sha256(p).hexdigest(),"
        "'removed':pathlib.Path('removed.txt').exists(),'cwd':os.getcwd()},sort_keys=True))\n"
    )
    workflow = repo / ".github/workflows/smoke.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("""name: Bundled SSH local hydration smoke
on:
  workflow_dispatch:
    inputs:
      crabbox_id: {required: true, type: string}
      crabbox_runner_label: {required: true, type: string}
      crabbox_keep_alive_minutes: {required: false, default: '0', type: string}
      crabbox_job: {required: false, default: hydrate, type: string}
jobs:
  hydrate:
    runs-on: ubuntu-latest
    env:
      CRABBOX_ID: ${{ inputs.crabbox_id }}
      CRABBOX_JOB: ${{ inputs.crabbox_job }}
    steps:
      - name: Read the newly synchronized source
        run: |
          mkdir -p hydrated
          cat hydration-input.txt > hydrated/result.txt
          printf '%s\\n' 'SMOKE_STEP_VALUE=from-first-step' >> "$GITHUB_ENV"
      - name: Verify step handoff and publish readiness
        run: |
          test "$SMOKE_STEP_VALUE" = from-first-step
          printf '%s\\n' "$SMOKE_STEP_VALUE" > hydrated/step-env.txt
          mkdir -p "$HOME/.crabbox/actions"
          state="$HOME/.crabbox/actions/$CRABBOX_ID.env"
          env_file="$HOME/.crabbox/actions/$CRABBOX_ID.env.sh"
          services_file="$HOME/.crabbox/actions/$CRABBOX_ID.services"
          printf '%s\\n' 'export CRABBOX_HYDRATED_SMOKE=from-hydration' > "$env_file"
          : > "$services_file"
          {
            printf 'WORKSPACE=%s\\n' "$GITHUB_WORKSPACE"
            printf 'RUN_ID=%s\\n' "$GITHUB_RUN_ID"
            printf 'JOB=%s\\n' "$CRABBOX_JOB"
            printf 'ENV_FILE=%s\\n' "$env_file"
            printf 'SERVICES_FILE=%s\\n' "$services_file"
            printf 'READY_AT=%s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          } > "$state.tmp"
          mv "$state.tmp" "$state"
""")
    runtime.run(["git", "init", "-q", "-b", "main", repo], env=environment)
    runtime.run(["git", "config", "core.autocrlf", "false"], cwd=repo, env=environment)
    runtime.run(["git", "add", "--", "."], cwd=repo, env=environment)
    runtime.run(["git", "-c", "user.name=Runtime Smoke", "-c", "user.email=smoke@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "workflow smoke"],
                cwd=repo, env=environment)
    attempted = False
    # Missing-origin plain-manifest mode intentionally disables fingerprints.
    # Supply the same real immutable bare origin to both Git clients; this lane
    # keeps overlay disabled so it still exercises manifest synchronization.
    origin_root = Path(tempfile.mkdtemp(prefix="crabbox-workflow-origin-", dir="/tmp"))
    try:
        origin = origin_root / (repo.name + ".git")
        runtime.run(["git", "clone", "--quiet", "--bare", repo, origin], env=environment)
        runtime.docker("cp", origin_root, "crabbox-runtime-smoke-" + token + ":/tmp/")
        runtime.run(["git", "remote", "add", "origin", origin.as_uri()], cwd=repo, env=environment)
        runtime.run(["git", "fetch", "--quiet", "origin"], cwd=repo, env=environment)
        origin_refs = runtime.run(["git", "for-each-ref", "--contains=HEAD", "--format=%(refname)",
                                   "refs/remotes/origin"], cwd=repo, env=environment).stdout
        require(b"refs/remotes/origin/main\n" in origin_refs,
                "fixture lacks real origin-tracking evidence required for Git coherence/fingerprints")
        attempted = True
        invoke([*common, "--sync-only"])
        assert_released("initial manifest sync")
        for phase, expected, removed in (("initial", original, True), ("modified", payload, False),
                                         ("unchanged", payload, False)):
            if phase == "modified":
                source.write_bytes(payload)
                (repo / "removed.txt").unlink()
            if phase == "unchanged":
                # Command-bearing runs invalidate reuse before workload mutation.
                # Publish a fresh receipt with sync-only, then prove that the
                # next unchanged command skips sync and actually executes.
                publication = invoke([*reused, "--sync-only"])
                receipts = remote_python(
                    "import json,pathlib,sys\n"
                    "root=pathlib.Path(sys.argv[1])\n"
                    "names=('sync-fingerprint','sync-finalize-token','sync-finalize-complete-token')\n"
                    "print(json.dumps({str(p.relative_to(root)):p.read_bytes()[:256].hex() "
                    "for base in (root/'.git/crabbox',root/'.crabbox') "
                    "for name in names for p in (base/name,) if p.is_file()}))\n", workspace).stdout
                assert_released("fingerprint receipt publication")
            capture = local / (phase + ".stdout")
            result = invoke([*reused, "--capture-stdout", capture, "--", "python3", "probe.py", phase])
            require(json.loads(capture.read_bytes()) == {
                "phase": phase, "sha256": hashlib.sha256(expected).hexdigest(),
                "removed": removed, "cwd": workspace,
            }, f"{phase}: real workload did not observe expected manifest contents")
            if phase == "unchanged":
                require(b"sync_skipped=true" in result.stderr,
                        runtime.failure_message("unchanged run did not use fingerprint reuse", result.stderr)
                        + "\npre-unchanged publication:\n" + runtime.diagnostic_tail(publication.stderr)
                        + "\npre-unchanged remote receipts (bounded hex):\n" + runtime.diagnostic_tail(receipts)
                        + "\nlocal origin tracking:\n" + runtime.diagnostic_tail(origin_refs))
            if phase == "modified":
                require(b"sync_skipped=false" in result.stderr,
                        "modified payload incorrectly selected fingerprint reuse")
            assert_released(phase)

        # A script file leaves CLI stdin available to the workload. Script-stdin
        # consumes stdin as source and cannot simultaneously carry runtime data.
        script = local / "standalone.py"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,pathlib,sys\n"
            "assert sys.argv[1:] == " + repr(literal) + "\n"
            "assert os.getcwd() == " + repr(workspace) + "\n"
            "assert pathlib.Path(__file__).parent.name == 'scripts'\n"
            "data=sys.stdin.buffer.read()\n"
            "pathlib.Path('script-output.bin').write_bytes(data)\n"
            "sys.stdout.buffer.write(data)\n"
            "sys.stderr.buffer.write(b'script stderr\\x00\\xff\\n')\n"
        )
        stdout = local / "script.stdout"
        stderr = local / "script.stderr"
        download = local / "script.download"
        invoke([*reused, "--no-sync", "--script", script, "--capture-stdout", stdout,
                "--capture-stderr", stderr, "--download", "script-output.bin=" + str(download),
                "--", *literal], data=original)
        observed_stdout, observed_download = stdout.read_bytes(), download.read_bytes()
        byte_diagnostics = {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                            for name, value in (("input", original), ("stdout", observed_stdout),
                                                ("download", observed_download), ("stderr", stderr.read_bytes()))}
        require(observed_stdout == original and observed_download == original,
                "--script binary stdin/stdout/download changed bytes: " + json.dumps(byte_diagnostics))
        require(stderr.read_bytes() == b"script stderr\0\xff\n", "--script stderr capture changed bytes")
        assert_released("script binary stdin")

        inline = (
            "#!/usr/bin/env python3\nimport json,os,pathlib,sys\n"
            "assert sys.argv[1:] == " + repr(literal) + "\n"
            "assert os.getcwd() == " + repr(workspace) + "\n"
            "assert pathlib.Path(__file__).parent.name == 'scripts'\n"
            "sys.stdout.buffer.write(b'inline\\x00\\xff\\n')\n"
            "sys.stderr.buffer.write(b'inline failure stderr\\n')\n"
            "raise SystemExit(37)\n"
        ).encode()
        stdout = local / "inline.stdout"
        stderr = local / "inline.stderr"
        result = invoke([*reused, "--no-sync", "--script-stdin", "--capture-stdout", stdout,
                         "--capture-stderr", stderr, "--", *literal], data=inline, check=False)
        require(result.returncode == 37, runtime.failure_message(
            f"--script-stdin expected exit 37, got {result.returncode}", result.stderr, result.stdout))
        require(stdout.read_bytes() == b"inline\0\xff\n" and
                stderr.read_bytes() == b"inline failure stderr\n", "nonzero script captures changed bytes")
        assert_released("script-stdin expected failure")
        lines = b"first line\nquotes ' $HOME ;\nlast line without newline"
        stdout = local / "lines.stdout"
        invoke([*reused, "--no-sync", "--capture-stdout", stdout, "--", "cat"], data=lines)
        require(stdout.read_bytes() == lines, "line stdin changed on reused CLI workload")
        assert_released("line stdin")
        for name, input_bytes in (("binary", original), ("lines", lines)):
            result = runtime.ssh_command(options, "cat", data=input_bytes)
            require(result.stdout == input_bytes and result.stderr == b"",
                    f"raw SSH {name} stdin roundtrip changed bytes (not a public CLI run probe)")

        # Full reset is intentionally before hydration: adopted Actions workspaces
        # have an additional readiness-invalidation/rehydration contract.
        remote_python("import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
                      "(p/'stale-workspace.txt').write_text('must disappear'); "
                      "(p/'.crabbox/stale-smoke').write_text('must disappear')", workspace)
        stdout = local / "reset.stdout"
        result = invoke([*reused, "--full-resync", "--capture-stdout", stdout, "--", "python3", "-c",
                         "import pathlib; assert not pathlib.Path('stale-workspace.txt').exists(); "
                         "assert not pathlib.Path('.crabbox/stale-smoke').exists(); "
                         "assert not pathlib.Path('script-output.bin').exists(); print('reset-workload-ran')"])
        require(stdout.read_bytes() == b"reset-workload-ran\n", "full-resync workload did not execute")
        require(b"sync_skipped=false" in result.stderr, "full-resync reused stale fingerprint")
        require(remote_python("import pathlib,sys; sys.stdout.buffer.write("
                              "(pathlib.Path(sys.argv[1])/\"payload 'quoted'.bin\").read_bytes())",
                              workspace).stdout == payload, "full-resync did not restore current source bytes")
        assert_released("full resync")

        for phase in ("first", "second"):
            expected = "hydration-" + phase + "\n"
            (repo / "hydration-input.txt").write_text(expected)
            result = invoke(["actions", "hydrate", "--provider", "ssh", "--target", "linux",
                             "--id", lease, "--workflow", ".github/workflows/smoke.yml", "--job", "hydrate",
                             "--wait-timeout", "2m", "--keep-alive-minutes", "0"])
            require(b"actions hydrated local" in result.stdout,
                    runtime.failure_message("local Actions hydration not confirmed", result.stderr, result.stdout))
            stdout = local / ("hydrated-" + phase + ".stdout")
            invoke([*reused, "--no-sync", "--capture-stdout", stdout, "--", "python3", "-c",
                    "import json,os,pathlib; print(json.dumps({'data':pathlib.Path('hydrated/result.txt').read_text(),"
                    "'step':pathlib.Path('hydrated/step-env.txt').read_text(),"
                    "'env':os.environ.get('CRABBOX_HYDRATED_SMOKE'),'cwd':os.getcwd()},sort_keys=True))"])
            require(json.loads(stdout.read_bytes()) == {"data": expected, "step": "from-first-step\n",
                    "env": "from-hydration", "cwd": workspace},
                    "Actions sync/step execution/step env/readiness handoff did not reach reused workload")
            assert_released("local hydration " + phase)
        print("PASS other real CLI workflows: manifest initial/change/delete, unchanged fingerprint reuse, "
              "full-resync stale-state removal, --script binary stdin/literal argv, --script-stdin literal argv/exit37, "
              "exact stdout+stderr captures/download, line stdin, two local Actions hydrations with changed source "
              "and environment handoff; ownership and sync staging released. Raw SSH binary/line stdin also passed "
              "independently (static SSH, not Kubernetes lifecycle)", flush=True)
    finally:
        primary_failure = sys.exc_info()[0] is not None
        cleanup_errors = []
        if attempted:
            try:
                result = invoke(["stop", "--provider", "ssh", lease], check=False)
                if result.returncode:
                    cleanup_errors.append(runtime.failure_message("workflow lease stop failed", result.stderr, result.stdout))
            except Exception as error:
                cleanup_errors.append(str(error))
        try:
            # The target container is exclusively owned by the surrounding harness.
            # Remove only this lane's root, Actions artifacts and owner gate records.
            runtime.docker("exec", "crabbox-runtime-smoke-" + token, "python3", "-c",
                           "import pathlib,shutil,sys\n"
                           "shutil.rmtree(sys.argv[1],ignore_errors=True)\n"
                           "shutil.rmtree(sys.argv[4],ignore_errors=True)\n"
                           "for root,prefix in [(pathlib.Path.home()/'.crabbox/actions',sys.argv[2]+'.'),"
                           "(pathlib.Path.home()/'.crabbox/workspace-owners',sys.argv[3]+'.')]:\n"
                           " for p in root.glob(prefix+'*'):\n"
                           "  if p.is_dir() and not p.is_symlink(): shutil.rmtree(p)\n"
                           "  else: p.unlink(missing_ok=True)\n", work_root, lease, owner_key, str(origin_root))
        except Exception as error:
            cleanup_errors.append(str(error))
        shutil.rmtree(origin_root)
        if cleanup_errors:
            message = "workflow cleanup: " + "\n".join(cleanup_errors)
            if primary_failure:
                print(message, file=sys.stderr, flush=True)
            else:
                raise runtime.SmokeFailure(message)

---
name: crabbox
description: "Use Crabbox for remote execution, repository verification, reusable leases, sync and artifact transfer. Use when crabbox.yaml or .crabbox.yaml exists, the crabbox CLI is available, or remote compute is needed."
license: MIT
---

# Crabbox

## Establish the execution contract once

- Follow the user's execution boundary. A remote-only workflow includes tests,
  builds, dependency installation, formatters and reproductions; local work is
  editing, source inspection, Git and forwarding remote execution.
- Read repository `crabbox.yaml` or `.crabbox.yaml` before executing its automation.
  Run from the intended Git repository. Normal sync requires Git and transfers
  tracked plus non-ignored untracked files, subject to configured exclusions.
- Resolve the binary with `command -v crabbox`; check `crabbox providers --json`
  once before depending on a provider. Keep the same binary, provider, repository
  and routing scope throughout the task. A source checkout or updated lockfile
  is not proof that the selected executable contains a fix.
- Prefer an existing project job, mise task or forwarding wrapper over inventing
  a second setup path. Read its inputs and output contract first.
- `crabbox config show` reports merged configuration. Use provider-specific
  `doctor` when diagnosing readiness, not as a ritual before every command.

## Provider boundaries

`agent-sandbox` delegates commands through Kubernetes and archive sync.
`agent-sandbox-ssh` uses the same warm pools through native SSH/rsync. They are
separate providers: a delegated lease is not an SSH lease and is not converted
by changing a flag. Keep custom pool/context/namespace settings on reuse or in
trusted configuration.

The SSH variant supports repository sync, scripts, captures and downloads. It
**does not provision desktops, browsers or code-server**. Generic command help
is not a capability promise. Delegated providers reject SSH-only features unless
`providers --json` and their provider docs explicitly advertise support.

Agent Sandbox is its own broker; it needs no separate coordinator login. Do not
respond to an unsupported history/copy command by setting up another broker or
managing Kubernetes pods directly. See `docs/providers/agent-sandbox.md` for the
specific provider contract; other providers have their own files there.

## Normal retained-workspace loop

**Default to one retained lease per session and repository.** Use `--keep` on
runs and reuse the recorded lease ID for setup, edits, verification and artifact
collection. Do not create and destroy a sandbox for every command. Reuse an
existing task-owned lease when its provider, repository, capabilities and
remaining lifetime fit; use separate leases for genuinely independent work.

```sh
crabbox warmup --slug example-check --ttl 24h
crabbox run --id example-check --keep -- mise run verify
crabbox cp --id example-check SANDBOX:/absolute/remote/result.json ./result.json
```

Use the actual per-lease/per-repository workdir printed by Crabbox; do not assume
`/workspace/crabbox` is the checkout. Warmup allocates a lease; it does not sync
source. If starting directly with `run`, pass `--keep` on that first invocation
too. Keep the lease across intermediate replies and handoffs; record its ID,
provider, repository, remote workdir and expiry. Release it explicitly at session
closeout only after required outputs are safe and no promised retained service
depends on it. Disposable one-shot runs are an intentional exception, not the
default. `--keep` does not extend hard TTL or prevent configured idle cleanup.

- **After local edits, use normal sync.** `--no-sync` deliberately runs retained
  remote source, not the new local files.
- `sync-plan` explains selected files and large candidates. It is preferable to
  repeatedly forcing large uploads or copying ignored dependencies.
- **`--fresh-sync` / `--full-resync` resets the remote workdir.** It is not a
  generic retry or a harmless way to refresh source. Preserve needed remote-only
  files first and use it only when a reset is actually intended.
- Keep bulk inputs, expensive outputs and retained caches outside the synced
  source tree when normal source replacement could affect them. Pull generated
  source changes back before syncing stale local copies over them.
- Use plain argv after `--` for one executable, `--shell` for shell syntax, and
  `--script` for standalone scripts. Uploaded scripts live in a content-hashed
  `.crabbox/scripts/` path: `$0`/`__file__` is not the original script location.
  Run a synced script in place if it requires adjacent files.

## Input, startup and cancellation

For unattended jobs with no input, explicitly close subprocess stdin using the
existing wrapper (`stdin=subprocess.DEVNULL` in Python or `stdio: ['ignore',
'pipe', 'pipe']` in Node). `pty:false` does not close a pipe. Do not close stdin
for an intentionally interactive workload or a command consuming supplied data.

Older POSIX workspace-owner launchers staged live input until EOF before starting
any command. Fork commit `814133d9` fixes that by keeping live input attached and
staging only finite control input. A live-input startup stall on a supposedly
patched installation is a version/deployment or regression investigation, not a
reason to teach every application a new workaround.

A lease-ready state or `running on ...` banner is not proof of workload startup.
Require fresh workload output/readiness and the matching completion receipt.
Avoid readiness patterns that can match the echoed command itself.

Stopping the local forwarder does not prove the remote process stopped. A
`state=child` owner wait protects a witnessed surviving workload. Inspect the
exact lease with native `status` and `connect`; wait for useful work or terminate
only the verified superseded process. Never delete owner markers, bypass locks,
or launch a competing build against active outputs.

## Timeouts and retention

The invoking tool deadline, provider execution deadline, idle timeout and hard
lease TTL are separate. Set long-command limits on the **run invocation**, not
only warmup. For long Agent Sandbox work, `--agent-sandbox-exec-timeout-secs 0`
removes the provider command deadline; give the invoking tool an appropriate
bound too. Keep a finite lease TTL large enough for cold builds and downloads.

Heartbeat/activity does not extend hard TTL. Detached processes do not imply
lease activity. Per-lease operation locks may serialize commands; use separate
leases for independent concurrent work. Do not patch Kubernetes shutdownTime or
claim expiry to bypass the lifecycle. Export required artifacts and custom Nix
closures before releasing or expiring scratch; verify transfers before cleanup.

## Failure triage and evidence

Identify the failed stage before retrying:

- **Admission/provider:** wrong binary, provider, scope or unsupported command.
  Correct that contract; do not repeat the rejected invocation.
- **Initialization:** preserve the retained lease and original error. A helper
  conflict needs runtime compatibility repair, not deleting aliases or replacing
  image tools by hand.
- **Sync:** retain the failing operation/path/stderr. Check `sync-plan` and the
  printed workdir. Do not turn an opaque prune failure into a blind full reset.
- **Ownership:** inspect the exact remote child and lease; do not remove locks.
- **User command:** missing tools, migrations or config trust belong to project
  setup. Run the existing setup task; do not reinstall infrastructure or treat
  application rejection as a transport failure.
- **Infrastructure:** distinguish actual node/storage/network failure from
  ordinary busy compilation. Preserve work and use the approved recovery path.

Keep the run handle, exit status and output from that invocation. A persistent
log or existing report may belong to an earlier run. Prefer per-run output paths.
On ordinary Linux SSH runs, `--require-artifact-change path` proves created or
changed bytes at an exact relative path; identical rewrites intentionally fail.
`--require-artifact` alone proves existence, not freshness.

Coordinator history commands require coordinator-backed records. Newer builds
with `--record-local` support opt-in local history and `--source local` readers;
check installed support before using them. Otherwise preserve native command
output/captures instead of repeatedly querying an unavailable coordinator.

For large files use native copy/download and compare final size/hash. Keep binary
stdout out of terminal previews. Do not assume a hangup or failed receipt means
no side effect occurred: inspect the specific output before repeating a transfer.

## Reference, not startup reading

Use the relevant `docs/commands/<command>.md` or `docs/providers/<provider>.md`
when an operation needs detail. Desktop, Windows, cloud login, publishing and
specialized GPU/Nix guidance are on-demand topics, not prerequisites for a normal
CPU test run. Stop only the leases owned by this task after retaining results.

# Agent Sandbox Provider

Read this when:

- choosing `provider: agent-sandbox` or `provider: agent-sandbox-ssh`;
- configuring a Kubernetes-backed Agent Sandbox warm pool;
- changing `internal/providers/agentsandbox`.

`agent-sandbox` is a delegated-run provider. Crabbox invokes `kubectl` against
the configured cluster, creates a `SandboxClaim` from a configured
`SandboxWarmPool`, waits for the resulting `Sandbox` and pod to become ready,
archive-syncs the local repository through `kubectl exec` and `tar`, runs the
command in the sandbox pod, and deletes the claim on release by default.

That archive variant has no Crabbox SSH lease. Kubernetes and Agent Sandbox own the runtime,
sandbox pod, and command transport. Crabbox owns local config, repo claims,
slug allocation, claim ownership labels and annotations, sync guardrails,
timing summaries, and normalized `list` / `status` output.

`agent-sandbox-ssh` is a separate SSH-lease provider using the same warm pools
and configuration. It bootstraps a private SSH daemon in the claimed container
and uses Crabbox's normal SSH sync and run path. Existing `agent-sandbox`
claims are not converted or reused by the SSH variant.

## When To Use

Use Agent Sandbox when your team already runs Agent Sandbox in Kubernetes and
wants Crabbox's local workflow, archive sync, repo claims, and command
streaming against a warm pool. It fits short Linux command execution where a
`SandboxClaim` is the durable unit of ownership.

Use `agent-sandbox-ssh` when you want `crabbox ssh`, SSH/rsync repository sync,
scripts, captures, and downloads against the same Kubernetes warm pool. It
does not provision desktop, browser, code-server, or Tailscale capabilities;
choose a provider advertising those features when you need them.

## SSH Variant: `agent-sandbox-ssh`

Select `provider: agent-sandbox-ssh` in the [config below](#config), or pass
`--provider agent-sandbox-ssh`. Keep the same `agentSandbox` config block,
`--agent-sandbox-*` flags, and `CRABBOX_AGENT_SANDBOX_*` environment variables;
there is no separate SSH-variant flag namespace. For example:

```sh
crabbox warmup --provider agent-sandbox-ssh \
  --agent-sandbox-context agent-cluster \
  --agent-sandbox-namespace sandboxes \
  --agent-sandbox-warm-pool linux-pool \
  --agent-sandbox-container worker \
  --slug linux-ssh-smoke
# Keep these routing settings in trusted config, or repeat them on reuse.
crabbox run --provider agent-sandbox-ssh --id linux-ssh-smoke -- go test ./...
crabbox run --provider agent-sandbox-ssh --id linux-ssh-smoke \
  --script ./scripts/check.sh --capture-stdout /tmp/check.stdout
crabbox ssh --provider agent-sandbox-ssh --id linux-ssh-smoke
crabbox stop --provider agent-sandbox-ssh linux-ssh-smoke
```

In addition to the Kubernetes prerequisites below, this variant requires:

- Local OpenSSH, `ssh-keygen`, and rsync, plus the configured `kubectl`.
  Generated SSH commands invoke the absolute path of the Crabbox executable
  that generated them as their proxy. Keep that executable and the local lease
  credentials available; a temporary build cannot be removed while its
  generated commands are still in use.
- RBAC `create` on `pods/portforward`, in addition to `pods/exec` and the
  claim/discovery permissions below. `doctor --provider agent-sandbox-ssh`
  checks the additional permission. No public SSH Service or ingress is needed.
- A Linux amd64 (`x86_64`) container running as root, with an existing UID-0
  `root` account and an absolute login shell resolving to an executable regular
  file. Empty account shell fields default to `/bin/sh`. `false` and `nologin`
  shells are rejected. The private daemon owns its root-shell policy and does
  not require an `/etc/shells` entry; it does not change another daemon's policy.
  The initializer never edits `/etc/passwd`, `/etc/shadow`, `/etc/group`, or
  `/etc/shells`, unlocks an account, or creates a service account.
- Initially available `uname`, `sh`, `mkdir`, `cat`, `chmod`, `rm`, and `rmdir`
  for architecture detection, byte upload, and cleanup. `/tmp` must be writable
  and allow execution. The workspace, private runtime/state paths, and any FHS
  directories needing missing tool links must be writable. Private directory
  ancestors must have safe root ownership and permissions.
- An image `PATH` containing only nonempty absolute directories, and compatible
  existing tools. A present tool that lacks required behavior is an error, not
  permission to replace it or select a bundled copy earlier in `PATH`.

### Additive initialization and SSH transport

The existing authenticated Kubernetes exec channel first checks the optional
`/opt/crabbox-seed/initialize` without executing it. An executable seed is used
only when its `sha256sum` matches the exact decompressed initializer bytes
embedded in the CLI. An absent, incompatible, or unhashable seed falls back to
uploading the Linux amd64 static Go initializer into a new private directory
under `/tmp`; actual Kubernetes exec/transport failures remain hard errors,
not evidence of seed absence. The initializer contains a compressed static
tool payload; no target package manager, package repository, shared-library
installation, or Nix store is needed. A separate exec invokes the selected
initializer with JSON on stdin carrying only the lease ID and client public
key. The client private key stays local. The host private key is generated and
retained only in the container; the returned host public key is pinned in the
local private per-lease `known_hosts` file. Kubernetes authentication and the
verified claim-to-sandbox-to-pod/container binding authorize this bootstrap,
not a key presented by an SSH connection.

The initializer can also reuse an optional sibling `payload` directory beside
its resolved executable, verified against the embedded payload before use.
An ordinary image can provide `/opt/crabbox-seed/{initialize,payload}`; a
symlinked layout can point `/opt/crabbox-seed` at an immutable Nix store output
containing both. Nix is optional. Unsafe, incomplete, or mismatched pre-extracted
payloads fail closed and are never repaired in the image. With no sibling
payload, the initializer stages a content-addressed runtime under
`/opt/crabbox-runtime/<payload-sha256>`. It checks existing command paths and
adds only missing `/bin` and `/usr/bin` symlinks, reusing a compatible image
tool where available and otherwise pointing to the bundled static executable.
Private SFTP and Git helper links live under `/usr/libexec`. Existing image
files and symlinks are neither replaced nor shadowed; conflicting tools or
helper paths fail initialization. The additions are visible to workloads and
remain for the Pod's lifetime. They are not a separate control-only filesystem.

A standalone Dropbear daemon runs independently of any existing SSH daemon,
with key-only root authentication and password authentication disabled. Its
host key, authorized keys, launch state, PID, and `dropbear.log` live under
`/var/lib/crabbox-ssh/<lease-id>`. It selects an available unprivileged loopback
port on first initialization and reuses the stored port and actual host key
while healthy; there is no fixed SSH port requirement. If a container restart
loses this ephemeral state, normal lease preparation generates a fresh key and
listener and refreshes the local endpoint and private `known_hosts` pin from
authenticated Kubernetes exec output. It requires no Kubernetes Secret or
manual pin reset. Initialization never takes over an unrelated daemon or its
port, and still rejects unsafe private files, conflicting process ownership,
and ambiguous PID-without-port state.

Every preparation checks seed compatibility, including on reuse. An exact
seed skips the initializer upload; fallback uploads the full initializer and
removes the temporary upload after invocation. Verified runtime content and
the matching healthy lease endpoint are reused, not reinstalled or assigned a
new identity. The amd64 initializer upload is approximately 36.2 MB, and
its compressed embedded asset is approximately 33.4 MB. These are approximate
artifact sizes, not total CLI binary sizes or a promise of incremental uploads.

The daemon inherits the container's pod-exec environment rather than a bounded
image-variable allowlist. Existing image `PATH` order is preserved; `/usr/bin`
and `/bin` are appended only if absent, without prepending the private runtime.
This does not forward the entire local client environment: local variables
still use Crabbox's normal explicit environment-forwarding rules. Core SSH
execution and bash-login-shell semantics are unchanged, so shell startup files
can still affect the eventual workload environment.

Kubernetes port-forwarding supplies the SSH transport, with claim, Sandbox,
pod, and container runtime identity checks before bootstrap, after bootstrap,
and before exposing a forwarded stream. A same-pod container restart invalidates
the prepared endpoint too. Bootstrap may re-resolve and retry a verified
replacement up to three attempts within the existing readiness/exec deadlines;
the original claim UID must still match. SSH host-key checking remains strict,
and workload commands are never replayed by this recovery path.

Read-only `status`, `list`, and `inspect` distinguish `pod_ready` from
`ssh_ready`. Their SSH check performs a pinned, client-key-authenticated
handshake but runs no remote command, initializes no daemon, and changes no
claim or trust file. A ready pod with a changed/unverified endpoint or unavailable
SSH is reported as `ssh-unavailable` (`status.ready=false`). A normal run,
copy, or SSH acquisition prepares the lease through Kubernetes again. Leases
created by an older CLI initially lack the runtime binding and need this normal
preparation before the new read-only checks can report SSH ready.

SSH then carries repository sync, command execution, scripts, captures, and
downloads through the existing core paths.
`agentSandbox.workdir` is the SSH work root; the run output prints the actual
lease/repository workdir beneath it. The image entrypoint and existing
processes, including Docker and unrelated SSH daemons, are not replaced. No
image rebuild, Pod-template mount changes, cluster rollout, Mutagen, or
`sandboxd` is involved in initialization.

This is a bounded supported-image contract, not an arbitrary-image adapter:
non-root, read-only-rootfs, shell-free/distroless, incompatible account/shell,
and incompatible-existing-tool images are rejected. Only Linux amd64 is
supported; other architectures are rejected before upload. The variant is
direct-only. It retains the shared TTL and UID-guarded claim cleanup rules.
With `agentSandbox.deleteOnRelease: false`, release retains the claim and its
SSH credentials rather than deleting them.

### Bundled tool limits

The payload supplies Bash, core shell/process utilities, rsync, Python and its
standard library, tar/gzip, a minimal Git with HTTP(S) helpers and CA data,
Dropbear, and an SFTP server. It is not a complete development environment:

- Bundled Git provides built-in commands and HTTP(S) transport, not Git's
  shell/Perl command suite or a full distribution Git installation.
- Its libcurl has no Unicode hostname conversion; use ASCII or punycode
  hostnames. It also lacks libpsl cookie public-suffix checking and libcurl
  SCP/SFTP transport. The SSH daemon's SFTP subsystem is independently
  supported; it does not rely on libcurl.
- Bundled tar does not preserve POSIX ACLs.

Compatible existing image tools remain in use and retain their own features;
the bundle does not upgrade or replace them.

### Building and checking the runtime

From the repository root, use the pinned Nix development environment and
runtime derivations through the build script:

```sh
bash scripts/build-agent-sandbox-runtime.sh
# Equivalent explicit architecture selection:
bash scripts/build-agent-sandbox-runtime.sh amd64
```

The script requires Nix with flakes/development-shell support and fetch access
to its pinned sources or caches. It supplies build tooling, checks payload ELF
architecture/static linkage and portable paths without executing payload code,
and generates `internal/providers/agentsandbox/assets/initializer-linux-amd64.gz`
for embedding in the CLI. Do not run concurrent producers: the build uses
`runtimes/agent-sandbox/payload.tar.gz` as a fixed intermediate, and the script
enforces an exclusive build lock. Only amd64 is accepted. Rebuild the CLI after
regenerating the canonical assets, not before: the CLI embeds their bytes at
build time. An image seed's `initialize` must be decompressed from that same
`internal/providers/agentsandbox/assets/initializer-linux-amd64.gz`; its optional
`payload` directory must be extracted from the matching
`runtimes/agent-sandbox/payload.tar.gz`. Do not mix independently generated
assets or regenerate the initializer after building the CLI.

Live CPU-worker proof with matching CLI/initializer artifacts covered absent
seed upload, exact-seed reuse with zero initializer uploads, and incompatible
seed fallback without executing the incompatible seed; real SSH preserved the
pinned host key and port. A separately built immutable Nix seed package passed
initialization and pinned SSH twice without private payload extraction or
account-file changes. This does not establish a full pool-image rollout or
compatibility with arbitrary images.

The Dropbear build includes a root-only shell-policy patch. For the existing
UID-0 `root` account, it accepts an absolute executable regular-file shell
without consulting the image's `/etc/shells`; `false` and `nologin` remain
rejected. Earlier account checks and the normal public-key authentication path
remain intact. This changes only the bundled private daemon, not the image's
account files, global shell policy, or unrelated SSH services.

The build also makes a narrow upstream numeric-bound adjustment:
`MAX_CMD_LEN` in `src/sysoptions.h` changes from 9,000 bytes to 256 KiB. That
upstream definition is unguarded, so it requires a checked source substitution
rather than a `localoptions.h` override. `RECV_MAX_PAYLOAD_LEN` is configured as
that bound plus 1 KiB for exec-request framing. Core sync now uploads generated
shell programs separately, but normal workload/ownership command wrappers can
still exceed the original limit. The numeric adjustment keeps a finite bound
without changing command parsing or authentication; it does not remove
operating-system argument-size limits.

Separately, POSIX core SSH sync stages generated scripts and their workspace
ownership checks in exclusive private `/tmp/crabbox-sync-script-*` directories,
then invokes a short `/bin/sh` command with sync data on stdin. Cleanup is
ownership-guarded and runs on success or failure. This is shared core behavior,
not an Agent Sandbox-specific command rewrite; normal workload execution and
Windows sync are unchanged. It keeps large sync source out of SSH exec
requests, rather than depending on the bundled daemon's larger command bound.

The Docker smoke requires native Linux amd64, a working Docker daemon, local
`ssh`, `ssh-keygen`, `sftp`, rsync, and Python 3. Generate matching initializer
and intermediate payload artifacts before running it:

```sh
bash scripts/build-agent-sandbox-runtime.sh amd64
uv run --no-project scripts/test-agent-sandbox-runtime.py
# Optional: build the CLI and also exercise its core SSH sync/run path.
env CGO_ENABLED=0 go build -trimpath -o bin/crabbox ./cmd/crabbox
uv run --no-project scripts/test-agent-sandbox-runtime.py --crabbox bin/crabbox
# Alternate matching artifacts or image references:
uv run --no-project scripts/test-agent-sandbox-runtime.py \
  --initializer internal/providers/agentsandbox/assets/initializer-linux-amd64.gz \
  --payload runtimes/agent-sandbox/payload.tar.gz \
  --debian-image debian:bookworm-slim --alpine-image alpine:3.22
```

The harness creates disposable Docker containers and fixture processes and
cleans up those it owns. Image pulls and the HTTPS Git check need network
access; runtime installation itself does not download packages. The Debian
case expects success; the raw Alpine case expects rejection for incompatible
existing `ps`/`flock`, not automatic replacement.

The optional `--crabbox` mode requires an existing executable CLI and local Git
including `git-http-backend` (plus Go to build the CLI as above). It uses isolated local config/state and
`provider=ssh` against the initialized Debian fixture with its pinned host key.
It checks initial `--sync-only` and changed/deleted-file resync with SSH exec
requests bounded to 9,000 bytes. Separate normal `--id --no-sync` workloads
check literal argv/environment/cwd, stdout capture, exact-byte downloads,
reuse, and exit status under the bundled daemon's 256 KiB bound. It does not
claim every CLI command fits the original 9,000-byte limit. This is a separate
core SSH-path check, not an
`agent-sandbox-ssh` Kubernetes lifecycle or port-forwarding check.

The same mode runs `scripts/agent_sandbox_git_smoke.py` against a real local
smart-HTTP Git origin with filtering advertised. The runner and host-networked
Debian container share that loopback endpoint; SSH, Git and rsync are not
mocked. Separate static leases exercise ordinary Git seeding and opt-in
`sync.gitOverlay`, rejecting unintended manifest fallback through CLI timing
reports and checking remote origin, HEAD, index tree, exact file bytes/types,
executable bits, status and completed sync metadata. It checks unchanged
fingerprint reuse without HTTP fetch, dirty tracked/untracked/deleted paths,
symlink changes, fetching the next committed revision, and full-resync/reseed.
Full resync intentionally selects ordinary manifest sync even when overlay is
enabled. Phase stdout/stderr remain in the fixture's temporary directory;
owned leases, remote workspaces and the HTTP server are cleaned up.

The same mode also runs `scripts/agent_sandbox_workflow_smoke.py`: initial and
changed/deleted-file sync, unchanged fingerprint reuse, full-resync removal of
stale workspace state, standalone scripts with literal arguments and binary
workload stdin, ordinary commands with line stdin, and source-only
`--script-stdin`. It checks exact stdout/stderr captures, binary downloads,
exit status 37, and two local Actions hydration runs with changed source and
step-to-step/environment handoff into a reused workload. Each phase checks
workspace-owner release and return of sync staging to its baseline; owned
leases and fixture state are cleaned up.

Verified scope: the Debian bookworm-slim amd64 runtime smoke passed pinned
key-only SSH and foreign-key rejection, exit status, exec above 16 KiB, literal argv/environment,
PTY, rsync, SFTP, Git commit/reset/HTTPS, tar/gzip, TCP forwarding, and endpoint
reuse. It also verified original tools/account files and an unrelated SSH
daemon remained intact. Existing root `/bin/bash` worked both without
`/etc/shells` and with a nonmatching shell list, preserving the original account
and tool files and unrelated SSH service. Raw Alpine 3.22 was correctly
rejected while preserving those originals. The native payload passed its
24-static-ELF build gate. Provider and initializer Go race tests and the
targeted uploaded-sync-script tests passed.

The optional actual core CLI smoke also passed against initialized Debian:
initial and changed/deleted-file sync requests peaked at 8,498 bytes; separate
normal no-sync workload requests peaked at 12,454 bytes while proving literal
argv/environment/cwd, exact-byte downloads, reuse, and exit status 37. Those
measurements describe the fixture, not universal maximum command sizes.

The additional script/input/capture/download/full-resync and two-run local
Actions hydration matrix above also passed through the real CLI against the
bundled Debian daemon. POSIX workload stdin now reaches only workload
execution, not upload, sync, or ownership controls, and is not replayed;
`--script-stdin` remains script source without a separate runtime input stream.
Native Windows, WSL, and delegated-provider input paths are unchanged. This
does not establish live Windows or additional Kubernetes lifecycle coverage.

The real smart-HTTP Git lane also passed all of the scenarios above against
the bundled Debian daemon: successful ordinary seed and Git overlay, both
unchanged reuse modes, dirty overlay bytes/types/status, committed advancement
and full-resync/reseed. This establishes successful Git workflow execution
through the public CLI's static-SSH path, independently of the earlier Nix
run's Git-seed fallback described below.

Separately, real `agent-sandbox-ssh` validation passed against the existing Nix
warm-pool worker with the final amd64-only CLI: warmup took 12.877 seconds,
2,238 repository files (96.8 MiB) synced, and Python asserted literal
argv/environment and the exact nested working directory. Local checks verified
an 870-byte stdout capture and exact 7,955-byte binary download. The same
pinned port, 42987, was reused successfully; that observed port is not a
configured default. A subsequent 65-second workload stayed connected through
renewal, returned exactly exit status 37, and released its workspace owner.
Docker 29.6.2 remained usable. `/etc/passwd` and
`/etc/group` remained their original Nix-store symlinks; `/etc/shadow`,
`/etc/gshadow`, and `/etc/shells` remained absent, with root still using
`/bin/bash`. The worker image matched the untouched archive-provider runner;
comparisons of those five account/policy paths matched byte hashes, symlink
targets, modes, UID/GID, and absence against that untouched runner. No account,
image, or template change was needed.

This live run used the existing plain-manifest sync fallback after a Git-seed
warning, so it does not prove metadata-based Git seeding. An initial run failed
closed on workspace renewal/context cancellation; an unchanged retry passed,
not evidence of a diagnosed or fixed cause. This verifies that worker image
and exercised paths, not arbitrary Nix images or failure-free operation. The
Docker runtime/static-SSH harness and the archive provider's live smoke below
remain distinct from this Kubernetes-provider proof.

## Prerequisites

- `kubectl` installed and compatible with the target cluster.
- A Kubernetes kubeconfig that can reach the target cluster. Standard
  `KUBECONFIG` and default kubeconfig resolution apply when
  `agentSandbox.kubeconfig` is empty.
  Configured kubeconfig paths and `KUBECONFIG` entries must be absolute after
  home expansion so repository files cannot become cluster credentials.
- A non-empty Kubernetes context. Crabbox requires the context so local claims
  cannot drift when the kubeconfig current context changes.
- A namespace containing Agent Sandbox resources.
- Agent Sandbox CRDs:
  - `agents.x-k8s.io/v1beta1` `sandboxes`
  - `extensions.agents.x-k8s.io/v1beta1` `sandboxclaims`
  - `extensions.agents.x-k8s.io/v1beta1` `sandboxwarmpools`
- A `SandboxWarmPool` in the configured namespace.
- RBAC allowing:
  - `get`, `create`, and `delete` on `sandboxclaims`
  - `get` on `sandboxwarmpools`
  - `get` on `sandboxes`
  - `get` and `list` on pods
  - `create` on `pods/exec`
- For the archive variant, a sandbox image that provides `/bin/sh`, `bash`, `tar`, `cp`, and a writable
  workdir. Crabbox uses `/bin/sh` for transport scripts and `bash -lc` for
  user shell-mode and auto-shell commands.
  Quoted and interpolated profile arguments remain literal through the stdin
  transport; workspace setup and environment export share the same command wrapper
  as Nomad without sharing Kubernetes lifecycle or execution machinery.

## Supported Agent Sandbox Version

Crabbox currently targets the Agent Sandbox `v0.5.0rc1` prerelease API:

- `agents.x-k8s.io/v1beta1`
- `extensions.agents.x-k8s.io/v1beta1`

This is intentional because `v0.5.0` is expected to promote the same beta API
soon. Crabbox does not carry `v1alpha1` compatibility. Until stable `v0.5.0`
ships, pin the controller and CRDs to `v0.5.0rc1` or a newer release that still
serves these `v1beta1` resources.

Official project and release references:

- [Agent Sandbox project](https://github.com/kubernetes-sigs/agent-sandbox)
- [Agent Sandbox v0.5.0rc1 release](https://github.com/kubernetes-sigs/agent-sandbox/releases/tag/v0.5.0rc1)

## Commands

These examples select the original archive/exec provider:

```sh
crabbox doctor --provider agent-sandbox
crabbox warmup --provider agent-sandbox --slug linux-pool-smoke
crabbox run --provider agent-sandbox -- go test ./...
crabbox run --provider agent-sandbox --id linux-pool-smoke --no-sync -- echo reused
crabbox run --provider agent-sandbox --id linux-pool-smoke --sync-only
crabbox status --provider agent-sandbox --id linux-pool-smoke --wait
crabbox list --provider agent-sandbox --json
crabbox stop --provider agent-sandbox linux-pool-smoke
crabbox cleanup --provider agent-sandbox --dry-run
```

## Live Smoke

The provider-specific live smoke is guarded by `CRABBOX_LIVE=1` and an explicit
provider selection. It builds `bin/crabbox` unless `CRABBOX_BIN` points at an
existing binary, verifies `doctor`, creates a short-lived `SandboxClaim`,
proves archive sync and env forwarding with a tiny Git fixture, reuses the
retained claim for a replacement-sync proof, checks status/list, then deletes
the claim.

```sh
CRABBOX_LIVE=1 CRABBOX_LIVE_PROVIDERS=agent-sandbox CRABBOX_LIVE_COORDINATOR=0 scripts/live-smoke.sh
# or, directly:
CRABBOX_LIVE=1 CRABBOX_LIVE_PROVIDERS=agent-sandbox scripts/live-agent-sandbox-smoke.sh
```

The script emits one machine-readable classification:
`live_agent_sandbox_smoke_passed`, `environment_blocked`, `quota_blocked`, or
`diagnostic_only`. Missing kubeconfig, context, warm pool, RBAC, cluster
connectivity, and API readiness issues are reported without pretending a live
mutation succeeded.

`warmup` keeps the sandbox available until explicit `stop` or the configured
Crabbox TTL expires. At expiry, the controller tears down the sandbox workload
but retains the `SandboxClaim` as an exact cleanup handle.
A `run` without `--id` creates a claim and deletes it after the command unless
`--keep` or `--keep-on-failure` retains it. The provider is Linux-only.
`run --lease-output <path>` writes the Agent Sandbox lease ID, slug,
reuse/retention state, and exact cleanup command for orchestration handoff.

## Config

Both variants use this configuration; change only `provider` to
`agent-sandbox-ssh` to select SSH for new leases. `execTimeoutSecs` bounds
provider pod-exec operations, including SSH bootstrap, not SSH workload runtime.

```yaml
provider: agent-sandbox
target: linux
agentSandbox:
  kubectl: kubectl                 # trusted user config only; binary name or absolute path
  kubeconfig: ~/.kube/config       # empty = KUBECONFIG/default kubeconfig
  context: agent-cluster           # required
  namespace: sandboxes             # default: default
  warmPool: linux-pool             # required SandboxWarmPool name
  container: worker                # empty = Kubernetes default container
  workdir: /workspace/crabbox      # default sync target and exec cwd
  sandboxReadyTimeout: 180s
  podReadyTimeout: 180s
  execTimeoutSecs: 600             # 0 = no provider command deadline
  deleteOnRelease: true
  forgetMissing: false
```

Repository-local `.crabbox.yaml` and `crabbox.yaml` files cannot override
`kubectl`, `kubeconfig`, `context`, `namespace`, `warmPool`, `container`, or
`workdir`.
Kubeconfig files may invoke credential plugins, and workload selection can
redirect forwarded source and environment values to another pod, so these
settings are accepted only from trusted user config, environment variables, or
explicit flags. The `kubectl` value must be a bare executable name resolved
through `PATH` or an absolute path; checkout-relative paths are rejected.

Provider flags:

```text
--agent-sandbox-kubectl
--agent-sandbox-kubeconfig
--agent-sandbox-context
--agent-sandbox-namespace
--agent-sandbox-warm-pool
--agent-sandbox-container
--agent-sandbox-workdir
--agent-sandbox-sandbox-ready-timeout
--agent-sandbox-pod-ready-timeout
--agent-sandbox-exec-timeout-secs
--agent-sandbox-delete-on-release
--agent-sandbox-forget-missing
```

Environment overrides use the `CRABBOX_AGENT_SANDBOX_*` prefix:

```text
CRABBOX_AGENT_SANDBOX_KUBECTL
CRABBOX_AGENT_SANDBOX_KUBECONFIG
CRABBOX_AGENT_SANDBOX_CONTEXT
CRABBOX_AGENT_SANDBOX_NAMESPACE
CRABBOX_AGENT_SANDBOX_WARM_POOL
CRABBOX_AGENT_SANDBOX_CONTAINER
CRABBOX_AGENT_SANDBOX_WORKDIR
CRABBOX_AGENT_SANDBOX_SANDBOX_READY_TIMEOUT
CRABBOX_AGENT_SANDBOX_POD_READY_TIMEOUT
CRABBOX_AGENT_SANDBOX_EXEC_TIMEOUT_SECS
CRABBOX_AGENT_SANDBOX_DELETE_ON_RELEASE
CRABBOX_AGENT_SANDBOX_FORGET_MISSING
```

`agentSandbox.workdir` must be absolute and cannot be a broad system directory
such as `/`, `/tmp`, `/usr`, `/var`, or `/home`. `namespace`, `warmPool`, and
`container` cannot contain whitespace or `/`.

## Lifecycle

The sequence below describes `agent-sandbox` archive/exec operations. The SSH
variant shares claim acquisition, readiness, and guarded release, but replaces
steps 4–5 with SSH bootstrap and the core SSH sync/run workflow above.

1. `doctor` uses `kubectl` discovery, verifies the exact `v1beta1` Agent
   Sandbox resources, verifies the configured warm pool, and checks the
   required RBAC verbs. It does not create a claim.
2. `warmup` or `run` without `--id` creates one `SandboxClaim` named
   `crabbox-<slug>-<lease-hash>` in the configured namespace. The claim points
   at `agentSandbox.warmPool`, sets `spec.lifecycle.shutdownTime` to the
   Crabbox TTL with `shutdownPolicy: Retain`, and carries Crabbox ownership
   labels plus annotations for provider scope, workdir, and container. If `kubectl create`
   loses its response after the API server accepted the object, Crabbox fetches
   that exact deterministic name and adopts it only after ownership, scope, and
   Kubernetes UID validation.
3. Crabbox waits for `SandboxClaim.status.sandbox.name`, fetches the matching
   `Sandbox`, waits for its Ready condition, then resolves the pod from the
   sandbox pod annotation or selector and waits for the pod Ready condition.
   A `Finished=True` Sandbox or a pod in `Succeeded`/`Failed` phase stops the
   wait immediately with the terminal reason instead of consuming the timeout.
   Every claim lookup must retain the Kubernetes UID returned by creation.
   The live claim must also keep pointing at the configured warm pool.
   Its shutdown time and retain policy must still match the absolute expiry
   pinned in the local claim.
   Before sync or command execution, the Sandbox must carry that claim UID and
   be controller-owned by the exact `SandboxClaim`; the pod must be
   controller-owned by that exact Sandbox UID. Crabbox pins both downstream UIDs
   and revalidates the full chain immediately before each pod exec, rejecting
   observed deletion, recreation, or redirection before sending source or
   forwarded values. When `agentSandbox.container` is empty, Crabbox resolves
   the pod's default container once, pins its name in the local lease, and
   always passes that exact container to `kubectl exec`.
4. Unless `--no-sync` is set, Crabbox builds a portable archive from the local
   Git file manifest and extracts it into the configured workdir with
   `kubectl exec`. With `sync.delete: true`, extraction happens in a
   hidden staging directory inside the workdir and replaces the workdir contents
   only after upload and extraction succeed, without renaming the workdir
   itself or requiring its parent directory to be writable. This remains valid
   when the workdir is a mounted volume.
5. The command runs through Kubernetes exec in the sandbox pod. Forwarded
   environment values are exported inside the streamed shell script, not placed
   on the local command line.
6. On release, Crabbox deletes only the owned `SandboxClaim` whose labels and
   provider-scope annotation and immutable Kubernetes UID match the local
   claim. Deletion sends that UID as an API-server precondition. The Agent
   Sandbox controller owns the resulting sandbox and pod teardown.

Retained-claim `run`, `stop`, and `cleanup` operations share a per-lease
cross-process lock. A concurrent stop or cleanup waits for the active command
to finish, then re-resolves the local claim before mutating Kubernetes.
`status --wait` returns immediately when the root `SandboxClaim` disappears,
while still polling temporary downstream Sandbox or pod readiness gaps.
Retained claims whose pinned TTL elapsed, or whose controller condition reports
`ClaimExpired` or `SandboxExpired`, return the terminal `expired` state without
waiting for missing downstream resources.

## Claim Scope And Cleanup Safety

Both variants' local claim IDs use the `asbx_` prefix. Provider identity keeps
their claims separate. The provider scope includes the
kubeconfig identity, context, namespace, warm pool, and container. Reusing,
listing, status-checking, stopping, or cleaning up a retained claim only
matches claims from the same scope. Kubernetes stores only a SHA-256
fingerprint of that scope, not the local kubeconfig path.

Before deleting a live `SandboxClaim`, Crabbox verifies:

- `crabbox.dev/provider` matches the selected variant (`agent-sandbox` or
  `agent-sandbox-ssh`)
- `crabbox.dev/lease-id=<local lease id>`
- `crabbox.dev/provider-scope=<SHA-256 scope fingerprint>`
- the current `metadata.uid` matches the UID pinned in the local claim
- `spec.warmPoolRef.name` matches the warm pool pinned in the local claim
- `spec.lifecycle.shutdownTime` and `shutdownPolicy: Retain` match the pinned
  Crabbox TTL expiry

Cleanup performs the same live identity validation before idle checks and
dry-run output, so a preview cannot claim that a replaced or redirected object
would be deleted. After the pinned TTL, the controller removes the Sandbox,
pod, and Service while retaining the exact UID-bearing `SandboxClaim`; Crabbox
then deletes that claim and its local lease through `run`, `stop`, or `cleanup`.

Missing Kubernetes claims are preserved locally by default because a 404 can be
ambiguous across clusters or accounts. Set `--agent-sandbox-forget-missing` or
`CRABBOX_AGENT_SANDBOX_FORGET_MISSING=true` only after confirming the claim is
gone in the intended cluster.

If readiness fails and Kubernetes also rejects the UID-preconditioned cleanup,
Crabbox retains a minimal `not-ready` local lease containing the claim name and
UID. Retry the printed `crabbox stop` command after restoring cluster access;
successful cleanup removes that recovery lease.

`cleanup` uses Crabbox's local idle-time policy. It deletes due live claims
after ownership validation, skips missing claims unless `forgetMissing` is
enabled, and reports every skipped or removed claim.

## Capabilities

The following list applies to the original `agent-sandbox` archive variant;
see [SSH Variant](#ssh-variant-agent-sandbox-ssh) for the SSH provider.

- SSH: no.
- Crabbox sync: yes, delegated archive upload and `tar` extraction through pod
  exec.
- Provider sync: no separate provider-native copy command.
- Env forwarding: yes, inside the remote shell script.
- Desktop / browser / code / VNC: no.
- Tailscale: no.
- Actions runner hydration: no.
- Coordinator broker: no. Agent Sandbox always runs direct from the CLI.
- Aliases: none.

## Gotchas

- For `agent-sandbox`, `--actions-runner` and Tailscale options are rejected because the provider is
  delegated-run only.
- `kubectl` is a runtime prerequisite, but Crabbox does not embed the
  Kubernetes Go client libraries. This keeps the CLI dependency and binary
  cost bounded and uses the operator's normal kubeconfig and auth plugins.
- Isolation strength is determined by the Agent Sandbox installation and
  `SandboxTemplate`: runtime class, gVisor or Kata configuration, service
  account, network policy, volumes, and node isolation remain cluster-operator
  responsibilities. A plain pod is not automatically a strong security
  boundary.
- `--checksum` and SSH/rsync-specific behavior do not apply to the pod-exec
  archive path.
- `--no-sync` creates the workdir but does not apply `sync.delete`; retained
  workspaces keep whatever was already present.
- The default container is Kubernetes' default container for the pod. Set
  `agentSandbox.container` when the sandbox pod has multiple containers.
- Kubernetes errors may include cluster resource names. Do not paste live
  errors into public issues without a redaction pass.

## Live Smoke

The guarded live smoke is opt-in and creates one short-lived Crabbox-owned
`SandboxClaim` only when explicit live configuration is present. Because the
smoke forces replacement sync and verifies that a remote-only stale file is
removed on retained reuse, it accepts cluster access, workload selectors, and
`workdir` only from environment variables or an explicit `CRABBOX_CONFIG` file
outside the active repository, not repository-local config:

```sh
CRABBOX_LIVE=1 \
CRABBOX_LIVE_COORDINATOR=0 \
CRABBOX_LIVE_PROVIDERS=agent-sandbox \
CRABBOX_AGENT_SANDBOX_KUBECTL=kubectl \
CRABBOX_AGENT_SANDBOX_KUBECONFIG=~/.kube/config \
CRABBOX_AGENT_SANDBOX_CONTEXT=agent-cluster \
CRABBOX_AGENT_SANDBOX_NAMESPACE=sandboxes \
CRABBOX_AGENT_SANDBOX_WARM_POOL=linux-pool \
scripts/live-agent-sandbox-smoke.sh
```

The smoke builds `bin/crabbox` unless `CRABBOX_BIN` points at an executable,
runs `doctor`, creates one claim with a unique or configured slug, proves
archive sync and environment forwarding, checks `status --wait` and `list
--json`, then stops only the slug it created using the Agent Sandbox provider.

It prints exactly one classification:

- `live_agent_sandbox_smoke_passed`
- `environment_blocked`
- `quota_blocked`
- `diagnostic_only`

`environment_blocked` is the expected safe result when live mode, provider
selection, kubeconfig, context, warm pool, RBAC, CRDs, or cluster connectivity
are missing. Unit tests cover those guardrails without touching Kubernetes.

The general dispatcher can run the same smoke:

```sh
CRABBOX_LIVE=1 \
CRABBOX_LIVE_COORDINATOR=0 \
CRABBOX_LIVE_PROVIDERS=agent-sandbox \
scripts/live-smoke.sh
```

## Related Docs

- [Provider backends](../provider-backends.md)
- [Provider authoring](../features/provider-authoring.md)
- [Provider decision matrix](README.md)
- [kubectl reference](https://kubernetes.io/docs/reference/kubectl/)

#!/usr/bin/env bash
set -euo pipefail

# Run via `bash scripts/build-agent-sandbox-runtime.sh [amd64]`.
# Nix provides pinned build tooling; no package manager runs in the target Pod.
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
runtime="$root/runtimes/agent-sandbox"
if [[ $# -gt 1 || ${1-amd64} != amd64 ]]; then
  printf 'usage: %s [amd64]\n' "$0" >&2
  exit 2
fi
if [[ ${CRABBOX_RUNTIME_BUILD_SHELL:-} != 1 ]]; then
  exec nix develop "path:$runtime" --command env CRABBOX_RUNTIME_BUILD_SHELL=1 bash "$root/scripts/build-agent-sandbox-runtime.sh" amd64
fi

# The payload is embedded from a fixed filename. Never race concurrent producers.
lock="$runtime/.build-lock"
if ! mkdir "$lock"; then
  printf 'another runtime build owns %s; do not run producers concurrently\n' "$lock" >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"; rmdir -- "$lock"' EXIT
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1
assets="$root/internal/providers/agentsandbox/assets"
mkdir -p "$assets"

payload=$(nix build --keep-going --no-link --print-out-paths "path:$runtime#payload-amd64")
# Inspect ELF metadata without executing payload binaries.
python3 - "$payload" "$work/payload.tar.gz" <<'PY'
import gzip
import io
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile

root = pathlib.Path(sys.argv[1]).resolve()
destination = sys.argv[2]
expected_machine = 'Advanced Micro Devices X86-64'
required = ('dropbear dropbearkey bash sh git rsync tar cat chmod cp mv rm rmdir mkdir '
            'mktemp stat date base64 wc tr cut sleep cmp sort uniq head tail tee dd '
            'readlink realpath touch env id kill find xargs grep sed awk flock ps '
            'python3 sftp-server gzip chown comm dirname basename sha256sum ln '
            'true false printf nohup timeout').split()
for name in required:
    p = root / 'bin' / name
    if not p.is_file() or not (p.stat().st_mode & 0o111):
        raise SystemExit(f'missing required executable: {p}')
for name in ('git-remote-http', 'git-remote-https', 'ca-bundle.crt'):
    if not (root / 'libexec/git-core' / name).is_file():
        raise SystemExit(f'missing Git HTTPS payload: {name}')
if not list((root / 'lib').glob('python*/encodings/__init__.py')):
    raise SystemExit('Python standard library missing')

files = sorted(root.rglob('*'), key=lambda p: p.relative_to(root).as_posix())
elf_count = 0
for p in files:
    rel = p.relative_to(root)
    if p.is_symlink():
        link = os.readlink(p)
        resolved = p.resolve(strict=True)
        if os.path.isabs(link) or not resolved.is_relative_to(root):
            raise SystemExit(f'nonportable symlink: {rel} -> {link}')
        continue
    if p.is_dir():
        continue
    if not p.is_file():
        raise SystemExit(f'unsupported payload file type: {rel}')
    data = p.read_bytes()
    if data.startswith(b'\x7fELF'):
        elf_count += 1
        header = subprocess.check_output(['readelf', '-hW', str(p)], text=True)
        if not re.search(r'Machine:\s*' + re.escape(expected_machine) + r'\s*$', header, re.M):
            raise SystemExit(f'wrong ELF architecture: {rel}')
        program = subprocess.check_output(['readelf', '-lW', str(p)], text=True)
        dynamic = subprocess.check_output(['readelf', '-dW', str(p)], text=True)
        if re.search(r'^\s*INTERP\s', program, re.M) or '(NEEDED)' in dynamic:
            raise SystemExit(f'not self-contained static ELF: {rel}')
        if re.search(r'\((?:RPATH|RUNPATH)\)', dynamic):
            raise SystemExit(f'unexpected dynamic runtime search path: {rel}')
        # Strip before checking strings so build-only DWARF paths cannot mask
        # or be confused with executable runtime dependencies. Nix normally
        # strips already; no binary rewriting to hide runtime references.
        section_headers = subprocess.check_output(['readelf', '-SW', str(p)], text=True)
        if re.search(r'\.debug_(?:info|str|line)\s', section_headers):
            raise SystemExit(f'unstripped executable (cannot audit runtime paths): {rel}')
        store_refs = re.findall(rb'/nix/store/[0-9a-z]{32}-[^\x00\s"\'<>]+', data)
        if store_refs:
            refs = sorted(set(ref.decode('utf-8', 'replace') for ref in store_refs))
            raise SystemExit(f'embedded store path in {rel}: {refs[:8]}')
    elif rel.parts[0] in ('bin', 'libexec') and p.stat().st_mode & 0o111:
        raise SystemExit(f'non-ELF executable in static payload: {rel}')
    elif rel.parts[0] != 'licenses' and b'/nix/store/' in data:
        raise SystemExit(f'Nix store dependency in runtime data: {rel}')

# GNU tar format has deterministic long-name extensions and works with Go's
# archive/tar. Always emit regular files, never hard links. No absolute links.
with open(destination, 'wb') as output:
    with gzip.GzipFile(filename='', fileobj=output, mode='wb', compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.GNU_FORMAT) as archive:
            for p in files:
                info = tarfile.TarInfo(p.relative_to(root).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = 0
                if p.is_symlink():
                    info.type = tarfile.SYMTYPE
                    info.mode = 0o777
                    info.linkname = os.readlink(p)
                    archive.addfile(info)
                elif p.is_dir():
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                else:
                    info.mode = 0o755 if p.stat().st_mode & 0o111 else 0o644
                    info.size = p.stat().st_size
                    with p.open('rb') as source:
                        archive.addfile(info, source)
print(f'verified {elf_count} static amd64 ELFs; wrote deterministic payload', file=sys.stderr)
PY
cp "$work/payload.tar.gz" "$runtime/payload.tar.gz"
(
  cd "$root"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o "$work/initializer-linux-amd64" ./runtimes/agent-sandbox
)
# Verify the delivered initializer too, including accidental CGO regressions.
python3 - "$work/initializer-linux-amd64" <<'PY'
import pathlib, re, subprocess, sys
p = pathlib.Path(sys.argv[1])
if not p.read_bytes().startswith(b'\x7fELF'):
    raise SystemExit('initializer is not ELF')
program = subprocess.check_output(['readelf', '-lW', str(p)], text=True)
dynamic = subprocess.check_output(['readelf', '-dW', str(p)], text=True)
if re.search(r'^\s*INTERP\s', program, re.M) or '(NEEDED)' in dynamic:
    raise SystemExit('initializer is not statically linked')
PY
gzip -n -9 -c "$work/initializer-linux-amd64" > "$work/initializer-linux-amd64.gz"
mv "$work/initializer-linux-amd64.gz" "$assets/initializer-linux-amd64.gz"
printf 'generated %s\n' "$assets/initializer-linux-amd64.gz"

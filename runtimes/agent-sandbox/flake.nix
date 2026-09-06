{
  description = "Self-contained musl tools for additive Agent Sandbox initialization";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/801bef6abd86b91e51083066b83fb354a11fc640";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      payload =
        let
          host = import nixpkgs { inherit system; };
          cross = import nixpkgs {
            localSystem = system;
            crossSystem = { config = "x86_64-unknown-linux-musl"; };
          };
          pkgs = cross.pkgsStatic;
          inherit (nixpkgs) lib;
          noNLS = package: package.overrideAttrs (old: {
            configureFlags = (old.configureFlags or [ ]) ++ [ "--disable-nls" ];
            doCheck = false;
            doInstallCheck = false;
          });
          bash = (pkgs.bashNonInteractive.override { forFHSEnv = true; }).overrideAttrs (old: {
            configureFlags = old.configureFlags ++ [
              "--disable-nls" "--disable-dynamic-loading"
              "DEBUGGER_START_FILE=/usr/share/bashdb/bashdb-main.inc"
            ];
          });
          openssl = pkgs.stdenv.mkDerivation {
            pname = "crabbox-openssl";
            inherit (pkgs.openssl) version src;
            nativeBuildInputs = [ host.perl ];
            dontAddStaticConfigureFlags = true;
            configurePhase = ''
              runHook preConfigure
              CC=${pkgs.stdenv.cc.targetPrefix}cc AR=${pkgs.stdenv.cc.targetPrefix}ar \
                perl Configure linux-x86_64 \
                --prefix=/usr --openssldir=/etc/ssl --libdir=lib \
                no-shared no-module no-engine no-tests no-ct
              runHook postConfigure
            '';
            installPhase = ''
              make DESTDIR="$out" install_sw
              mv "$out/usr/"* "$out/"
              rmdir "$out/usr"
              substituteInPlace "$out/lib/pkgconfig/"*.pc \
                --replace-fail 'prefix=/usr' "prefix=$out"
            '';
            enableParallelBuilding = true;
            doCheck = false;
          };
          dropbear = (pkgs.dropbear.override {
            sftpPath = "/usr/libexec/crabbox-sftp-server";
          }).overrideAttrs (old: {
            # Upstream -e preserves the environment. The Nix-only pass-path
            # patch is unnecessary and its assumptions must not leak here.
            # Only this private daemon permits root's executable login shell
            # without the image's /etc/shells allowlist; other auth checks stay.
            patches = [ ./dropbear-root-shell.patch ];
            env = (old.env or { }) // { CFLAGS = "-Os"; };
            preConfigure = ''
              # Upstream's unguarded 9000-byte sysoptions bound cannot be
              # overridden by localoptions. Core's generated plain-manifest
              # command already exceeds it; --crabbox smoke exercises that
              # unchanged path. Keep a finite 256 KiB bound, above Linux's
              # usual 128 KiB single-argument limit, without changing parsing.
              substituteInPlace src/sysoptions.h \
                --replace-fail '#define MAX_CMD_LEN 9000' '#define MAX_CMD_LEN 262144'
              cat > localoptions.h <<'OPTIONS'
              #define DROPBEAR_SVR_PASSWORD_AUTH 0
              #define DROPBEAR_SVR_PAM_AUTH 0
              #define DROPBEAR_SVR_PUBKEY_AUTH 1
              #define DROPBEAR_SFTP 1
              #define DROPBEAR_PLUGIN 0
              #define SFTPSERVER_PATH "/usr/libexec/crabbox-sftp-server"
              #define DROPBEAR_PATH_SSH_PROGRAM "/usr/bin/ssh"
              /* Leave 1 KiB for the exec request framing around the command. */
              #define RECV_MAX_PAYLOAD_LEN (MAX_CMD_LEN + 1024)
              /* -e preserves the initializer's additive image PATH. These
               * macros are runtime addnewvar() arguments, not literals. */
              #define DEFAULT_PATH (getenv("PATH") ? getenv("PATH") : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
              #define DEFAULT_ROOT_PATH DEFAULT_PATH
              OPTIONS
              makeFlagsArray=(PROGRAMS="dropbear dropbearkey")
            '';
            configureFlags = [
              "--enable-static" "--disable-pam" "--disable-syslog"
              "--enable-utmp=no" "--enable-utmpx=no"
              "--enable-wtmp=no" "--enable-wtmpx=no" "--enable-lastlog=no"
            ];
            doCheck = false;
          });
          sftp = (pkgs.openssh.override {
            withPAM = false;
            withKerberos = false;
            withLdns = false;
            withFIDO = false;
            withSecurityKey = false;
            isNixos = false;
            inherit openssl;
          }).overrideAttrs (old: {
            # Do not build/package another SSH daemon or its account machinery.
            outputs = [ "out" ];
            # Without an explicit path, configure appends its own $bindir.
            configureFlags = old.configureFlags ++ [
              "--with-default-path=/usr/local/bin:/usr/bin:/bin"
            ];
            buildFlags = [ "sftp-server" ];
            installPhase = ''
              runHook preInstall
              mkdir -p "$out/libexec"
              cp sftp-server "$out/libexec/sftp-server"
              runHook postInstall
            '';
            postInstall = "";
            postFixup = "";
            doCheck = false;
            doInstallCheck = false;
          });
          curl = (pkgs.curl.override {
            inherit openssl;
            # Git and libidn2 both export gnulib's error() in static builds.
            # ASCII/punycode HTTPS remains available without IDN conversion
            # or libpsl's cookie public-suffix checks (which also use libidn2).
            idnSupport = false;
            pslSupport = false;
            # Git's HTTP(S) transports need neither QUIC nor libcurl SSH.
            # Their libraries otherwise bring a second, Nix-prefixed OpenSSL.
            http3Support = false;
            scpSupport = false;
          }).overrideAttrs (old: {
            configureFlags = lib.filter (flag: !(lib.hasPrefix "--with-ca-" flag)) (old.configureFlags or [ ]) ++ [
              "--with-ca-bundle=/usr/libexec/crabbox-git-core/ca-bundle.crt"
              "--without-ca-path"
            ];
            doCheck = false;
            doInstallCheck = false;
          });
          # Use the pinned pkgsStatic source/dependencies without Nix's
          # hardcoded shell/helper paths or post-install script rewriting.
          git = pkgs.stdenv.mkDerivation {
            pname = "crabbox-git";
            inherit (pkgs.git) version src;
            nativeBuildInputs = [ host.pkg-config host.perl ];
            buildInputs = [ curl openssl pkgs.zlib pkgs.expat ];
            # Upstream's Makefile handles the explicit target feature flags;
            # configure otherwise probes by executing cross-built binaries.
            dontConfigure = true;
            makeFlags = [
              "prefix=/usr" "bindir=/usr/bin"
              "gitexecdir=/usr/libexec/crabbox-git-core"
              "template_dir=/usr/libexec/crabbox-git-core/templates"
              "sysconfdir=/etc" "SHELL_PATH=/bin/sh"
              "NO_PERL=1" "NO_PYTHON=1" "NO_GETTEXT=1" "NO_TCLTK=1"
              "NO_RUST=1" "NO_INSTALL_HARDLINKS=1" "NO_SYS_POLL_H=1"
              # musl lacks REG_STARTEND; use Git's bundled regex engine.
              "NO_REGEX=NeedsStartEnd"
              "CURL_CONFIG=${lib.getDev curl}/bin/curl-config"
              "CC=${pkgs.stdenv.cc.targetPrefix}cc"
              "AR=${pkgs.stdenv.cc.targetPrefix}ar"
            ];
            buildFlags = [ "git" "git-remote-http" "git-http-fetch" "git-http-push" ];
            postPatch = ''
              # Preserve upstream's complete built-in alias set without
              # building unrelated mail, credential, test, or script tools.
              cat >> Makefile <<'MAKE'
              .PHONY: crabbox-install
              crabbox-install:
              	$(INSTALL) -d '$(DESTDIR_SQ)$(bindir_SQ)' '$(DESTDIR_SQ)$(gitexec_instdir_SQ)'
              	$(INSTALL) -m 755 git '$(DESTDIR_SQ)$(bindir_SQ)/git'
              	$(INSTALL) -m 755 git-remote-http git-http-fetch git-http-push '$(DESTDIR_SQ)$(gitexec_instdir_SQ)'
              	for p in git $(BUILT_INS); do ln -s ../../bin/git '$(DESTDIR_SQ)$(gitexec_instdir_SQ)'/$$p; done
              	ln -s git-remote-http '$(DESTDIR_SQ)$(gitexec_instdir_SQ)/git-remote-https'
              	for p in git-upload-pack git-receive-pack git-upload-archive; do ln -s git '$(DESTDIR_SQ)$(bindir_SQ)'/$$p; done
              MAKE
            '';
            preBuild = ''
              makeFlagsArray+=("SHELL=$SHELL" "LDFLAGS=-static" "CURL_LDFLAGS=$(${lib.getDev curl}/bin/curl-config --static-libs)")
            '';
            installTargets = "crabbox-install";
            installFlags = [ "DESTDIR=\${out}" ];
            # The FHS staging prefix sits outside stdenv's default strip dirs.
            stripDebugList = [ "usr/bin" "usr/libexec" ];
            enableParallelBuilding = true;
            dontPatchShebangs = true;
            doCheck = false;
          };
          python = (pkgs.python3Minimal.override {
            # Target static linkage follows pkgsStatic's hostPlatform. An
            # explicit static=true is propagated by CPython's argument splice
            # machinery to its native build interpreter (glibc), incorrectly
            # requiring static glibc there too.
            __splices = {
              pythonOnBuildForBuild = host.python3;
              pythonOnBuildForHost = host.python3;
            };
            reproducibleBuild = true;
            enableOptimizations = false;
            enableLTO = false;
            includeSiteCustomize = false;
            # Static CPython uses --disable-test-modules, which also omits
            # TESTSUBDIRS during installation. Nixpkgs' stripTests cleanup
            # expands its unmatched globs to an operandless `rm -R`.
            stripTests = false;
            allowedReferenceNames = [ ];
          }).overrideAttrs (old: {
            postPatch = (old.postPatch or "") + ''
              substituteInPlace Lib/subprocess.py \
                --replace-fail "'${pkgs.bashNonInteractive}/bin/sh'" "'/bin/sh'"
              # getpath first searches relative to the resolved executable.
              # Make the fallback FHS-based rather than the build store prefix.
              substituteInPlace Modules/getpath.c \
                --replace-fail '"PREFIX", PREFIX' '"PREFIX", "/usr"' \
                --replace-fail '"EXEC_PREFIX", EXEC_PREFIX' '"EXEC_PREFIX", "/usr"' \
                --replace-fail '"PYTHONPATH", PYTHONPATH' '"PYTHONPATH", ""' \
                --replace-fail '"VPATH", VPATH' '"VPATH", ""'
            '';
            allowedReferences = null;
            doCheck = false;
            doInstallCheck = false;
          });
          attr = pkgs.attr.overrideAttrs (old: {
            postPatch = (old.postPatch or "") + ''
              # Keep installation in the derivation, but consult the image's
              # existing optional policy file at runtime without creating it.
              substituteInPlace libattr/attr_copy_action.c \
                --replace-fail 'SYSCONFDIR "/xattr.conf"' '"/etc/xattr.conf"'
            '';
            doCheck = false;
          });
          acl = pkgs.acl.override { inherit attr; };
          coreutils = (noNLS (pkgs.coreutils.override { inherit attr acl; })).overrideAttrs (old: {
            # stdbuf requires a shared LD_PRELOAD helper and is not part of
            # this static runtime. Its link-only configure probe can succeed
            # on the cross toolchain, embedding helper paths in every applet.
            configureFlags = old.configureFlags ++ [ "utils_cv_stdbuf_supported=no" ];
          });
          findutils = (noNLS pkgs.findutils).overrideAttrs (old: {
            # Nix's only postPatch change makes xargs' default echo absolute.
            # Retain upstream PATH lookup so additive image tools are honored.
            postPatch = "";
            configureFlags = lib.filter (flag: !(lib.hasPrefix "SORT=" flag)) old.configureFlags ++ [ "ac_cv_path_SORT=sort" ];
          });
          grep = noNLS pkgs.gnugrep;
          sed = noNLS pkgs.gnused;
          awk = (noNLS pkgs.gawk).overrideAttrs (old: {
            configureFlags = old.configureFlags ++ [ "--disable-extensions" ];
            postPatch = (old.postPatch or "") + ''
              substituteInPlace Makefile.am \
                --replace-fail '$(PATH_SEPARATOR)$(pkgdatadir)' '$(PATH_SEPARATOR)/usr/share/awk' \
                --replace-fail 'DEFLIBPATH="\"$(pkgextensiondir)\""' 'DEFLIBPATH="\"/usr/lib/gawk\""'
            '';
          });
          # Sync/artifact archives use ordinary file metadata, not POSIX ACLs.
          # Avoid libacl 2.4's xattrat symbols colliding with tar's gnulib
          # replacements when both libraries are linked statically.
          tar = (noNLS (pkgs.gnutar.override { aclSupport = false; })).overrideAttrs (old: {
            # This is the remote host's optional tape helper, not a payload
            # dependency. Never compile the local Nix installation prefix.
            configureFlags = old.configureFlags ++ [ "--with-rmt=/usr/libexec/rmt" ];
          });
          gzip = (noNLS pkgs.gzip).overrideAttrs (_: {
            # Nix wraps gzip to honor its build-only GZIP_NO_TIMESTAMPS var.
            # Ship upstream's ELF directly; payload archives request -n.
            preFixup = "";
          });
          # OpenSSL is only optional hashing acceleration here. The built-in
          # implementations avoid linking the Nix OpenSSL configuration path.
          rsync = noNLS (pkgs.rsync.override { enableOpenSSL = false; inherit acl; });
          util = noNLS pkgs.util-linuxMinimal;
          procps = noNLS pkgs.procps;
          diffutils = (noNLS pkgs.diffutils).overrideAttrs (old: {
            configureFlags = lib.filter (flag: !(lib.hasPrefix "PR_PROGRAM=" flag)) old.configureFlags ++ [ "ac_cv_path_PR_PROGRAM=pr" ];
            postPatch = (if (old.postPatch or null) == null then "" else old.postPatch) + ''
              # Upstream execv requires an absolute configure-time pr path.
              # Resolve the shipped or image-provided command through PATH.
              substituteInPlace src/util.c \
                --replace-fail 'execv (pr_program,' 'execvp (pr_program,'
            '';
          });
          tools = [ bash dropbear coreutils findutils grep sed awk tar gzip rsync util procps diffutils ];
          # Preserve source notices through the linked-input graph, not only
          # the top-level tools (static linking carries library obligations).
          licenseRoots = tools ++ [ git python sftp curl pkgs.musl openssl pkgs.stdenv.cc.cc ];
          licensed = map (item: item.package) (builtins.genericClosure {
            startSet = map (package: { key = package.outPath; inherit package; }) licenseRoots;
            operator = item: map (package: { key = package.outPath; inherit package; }) (
              lib.filter (package: lib.isDerivation package && package ? src && package ? pname)
                ((item.package.buildInputs or [ ]) ++ (item.package.propagatedBuildInputs or [ ]))
            );
          });
          notices = host.runCommand "crabbox-runtime-licenses" { nativeBuildInputs = [ host.python3 host.libarchive ]; } ''
            mkdir -p "$out"
            ${lib.concatMapStringsSep "\n" (package: ''
              python3 - ${package.src} "$out/${package.pname}-${package.version or "unknown"}" <<'PY'
            import pathlib, re, shutil, stat, subprocess, sys, tempfile
            source, out = map(pathlib.Path, sys.argv[1:])
            names = ('COPYING', 'LICENSE', 'LICENCE', 'COPYRIGHT', 'NOTICE')
            def notice(name):
                return pathlib.PurePosixPath(name).name.upper().startswith(names)
            def destination(name):
                relative = pathlib.PurePosixPath(name)
                if relative.is_absolute() or '..' in relative.parts:
                    raise RuntimeError(f'unsafe notice member {name!r}')
                dst = out.joinpath(*relative.parts)
                dst.parent.mkdir(parents=True, exist_ok=True)
                return dst
            try:
                if source.is_dir():
                    candidates = [p for p in source.rglob('*') if p.is_file() and notice(p.name)]
                    if not candidates:
                        raise RuntimeError('source directory contains no license notices')
                    for p in candidates:
                        shutil.copyfile(p, destination(p.relative_to(source).as_posix()))
                else:
                    # libarchive identifies tar/zip and their compression by
                    # contents, including .tar.lz; source filenames need not
                    # retain the upstream suffix in the Nix store.
                    listing = subprocess.run(['bsdtar', '-tf', str(source)], text=True, capture_output=True)
                    if listing.returncode == 0:
                        candidates = [name for name in listing.stdout.splitlines() if notice(name) and not name.endswith('/')]
                        if not candidates:
                            raise RuntimeError('source archive contains no license notices')
                        # Decompress once, not once per notice (GCC and Python
                        # contain many). Only selected paths enter this private
                        # scratch directory; libarchive rejects path traversal.
                        for name in candidates:
                            relative = pathlib.PurePosixPath(name)
                            if relative.is_absolute() or '..' in relative.parts:
                                raise RuntimeError(f'unsafe notice member {name!r}')
                        with tempfile.TemporaryDirectory() as scratch:
                            subprocess.run(['bsdtar', '-xf', str(source), '-C', scratch,
                                            '--no-same-owner', '--no-same-permissions', '--', *candidates], check=True)
                            scratch = pathlib.Path(scratch)
                            for name in candidates:
                                notice_file = scratch / name
                                for part in (notice_file, *notice_file.parents):
                                    if part == scratch:
                                        break
                                    if part.is_symlink():
                                        raise RuntimeError(f'notice is reached through a symlink: {name!r}')
                                if not stat.S_ISREG(notice_file.lstat().st_mode):
                                    raise RuntimeError(f'notice is not a regular file: {name!r}')
                                shutil.copyfile(notice_file, destination(name))
                    else:
                        # Some single-file libraries carry the license in the
                        # source itself. Preserve that source in full, but do
                        # not invent a notice from metadata or ignore binaries.
                        content = source.read_bytes()
                        text = content.decode('utf-8')
                        if '\x00' in text or not re.search(r'copyright|permission is hereby granted|SPDX-License-Identifier|licensed under', text, re.I):
                            raise RuntimeError('not a recognized source archive or standalone licensed source: ' + listing.stderr.strip())
                        destination('SOURCE.txt').write_bytes(content)
            except Exception as error:
                raise SystemExit(f'license collection for {out.name}, source {source}: {error}') from error
            PY
            '') licensed}
          '';
        in host.runCommand "crabbox-agent-sandbox-payload-amd64" {
          nativeBuildInputs = [ host.python3 ];
        } ''
          mkdir -p "$out/bin" "$out/libexec/git-core" "$out/lib" "$out/licenses"
          ${lib.concatMapStringsSep "\n" (package: ''
            for file in ${lib.getBin package}/bin/*; do
              test -f "$file" || continue
              ${lib.optionalString (package == util) ''test "$(basename "$file")" = flock || continue''}
              ${lib.optionalString (package == procps) ''test "$(basename "$file")" = ps || continue''}
              # Only ELF executables are imported from Nix packages. Shell
              # wrappers and utility scripts are not a portable static runtime.
              if test "$(od -An -tx1 -N4 "$file" | tr -d ' \n')" = 7f454c46; then
                cp -L "$file" "$out/bin/$(basename "$file")"
              fi
            done
          '') tools}
          cp -L ${git}/usr/bin/git "$out/bin/git"
          for file in ${git}/usr/libexec/crabbox-git-core/*; do
            test -f "$file" || continue
            if test "$(od -An -tx1 -N4 "$file" | tr -d ' \n')" = 7f454c46; then
              cp -L "$file" "$out/libexec/git-core/$(basename "$file")"
            fi
          done
          # Builtin commands dispatch through the single binary. Nix/Git may
          # install many identical files; represent them as internal aliases.
          python3 - "$out" <<'PY'
          import hashlib, os, pathlib, sys
          root = pathlib.Path(sys.argv[1])
          seen = {}
          for p in sorted([*root.joinpath('bin').iterdir(), *root.joinpath('libexec/git-core').iterdir()]):
              digest = hashlib.sha256(p.read_bytes()).digest()
              if digest in seen:
                  target = os.path.relpath(seen[digest], p.parent)
                  p.unlink()
                  p.symlink_to(target)
              else:
                  seen[digest] = p
          PY
          ln -sfn bash "$out/bin/sh"
          if ! test -e "$out/bin/awk"; then ln -s gawk "$out/bin/awk"; fi
          cp -L ${sftp}/libexec/sftp-server "$out/bin/sftp-server"
          cp -L ${python}/bin/python3 "$out/bin/python3"
          cp -RL ${python}/lib/python${python.pythonVersion} "$out/lib/"
          # No development sysconfig, bytecode, package installation or scripts
          # are required by the manifest interpreter contract.
          find "$out/lib" -type d \( -name __pycache__ -o -name site-packages -o -name 'config-*' \) -prune -exec rm -rf {} +
          find "$out/lib" -type f \( -name '*.pyc' -o -name '_sysconfigdata*' -o -name '_sysconfig_vars*' \) -delete
          # PEP 739 describes the original development installation, not this
          # manifest-only runtime; fetch_macholib is an upstream SVN updater.
          rm "$out/lib/python${python.pythonVersion}/build-details.json" \
            "$out/lib/python${python.pythonVersion}/ctypes/macholib/fetch_macholib"
          find "$out/lib" -type f -exec chmod 644 {} +
          mkdir -p "$out/lib/python${python.pythonVersion}/lib-dynload"
          mkdir -p "$out/libexec/git-core/templates"
          cp ${host.cacert}/etc/ssl/certs/ca-bundle.crt "$out/libexec/git-core/ca-bundle.crt"
          chmod 644 "$out/libexec/git-core/ca-bundle.crt"
          cp -R ${notices}/. "$out/licenses/"
          printf '%s\n' 'nixpkgs 801bef6abd86b91e51083066b83fb354a11fc640' > "$out/licenses/SOURCES"
        '';
    in {
      packages.${system} = {
        payload-amd64 = payload;
        default = payload;
      };
      devShells.${system} =
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell { packages = [ pkgs.go pkgs.python3 pkgs.binutils pkgs.gzip pkgs.gnutar ]; }; };
    };
}

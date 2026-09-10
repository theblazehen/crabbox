package agentsandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
	xssh "golang.org/x/crypto/ssh"
)

const (
	claimLabelSSHPort       = "ssh_port"
	sshProxyReadyTimeout    = 30 * time.Second
	sshProxyOutputLineLimit = 4096
)

func validSSHBootstrapPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1024 && n <= 65535 && strconv.Itoa(n) == port
}

func closeClaimSSHMasters(ctx context.Context, claim LeaseClaim) error {
	key, err := core.TestboxKeyPath(claim.LeaseID)
	if err != nil {
		return err
	}
	return core.CloseSSHControlMasters(ctx, core.SSHTarget{Key: key})
}

func (b *backend) sshTarget(claim LeaseClaim) (core.SSHTarget, error) {
	if err := authorizeClaimScope(b.cfg, claim); err != nil {
		return core.SSHTarget{}, err
	}
	port := claim.Labels[claimLabelSSHPort]
	if !validSSHBootstrapPort(port) {
		return core.SSHTarget{}, fmt.Errorf("agent-sandbox-ssh lease %s has no valid pinned SSH port; prepare the lease again", claim.LeaseID)
	}
	user := strings.TrimSpace(claim.Labels[claimLabelSSHUser])
	hostKey := strings.TrimSpace(claim.Labels[claimLabelSSHHostKey])
	if user == "" || strings.ContainsAny(user, " \t\r\n@/\\") || strings.HasPrefix(user, "-") {
		return core.SSHTarget{}, fmt.Errorf("agent-sandbox-ssh lease %s has no valid pinned SSH user; prepare the lease again", claim.LeaseID)
	}
	_, _, options, rest, err := xssh.ParseAuthorizedKey([]byte(hostKey))
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || strings.ContainsAny(hostKey, "\r\n") {
		return core.SSHTarget{}, fmt.Errorf("agent-sandbox-ssh lease %s has no valid pinned SSH host key; prepare the lease again", claim.LeaseID)
	}
	key, err := core.TestboxKeyPath(claim.LeaseID)
	if err != nil {
		return core.SSHTarget{}, err
	}
	if info, err := os.Stat(key); err != nil || !info.Mode().IsRegular() {
		return core.SSHTarget{}, fmt.Errorf("agent-sandbox-ssh lease %s is missing its stored SSH private key; prepare the lease again", claim.LeaseID)
	}
	executable, err := os.Executable()
	if err != nil {
		return core.SSHTarget{}, fmt.Errorf("locate crabbox for SSH proxy: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return core.SSHTarget{}, fmt.Errorf("resolve crabbox SSH proxy executable: %w", err)
	}
	args, childEnv := b.sshProxyArgs(executable, claim.LeaseID)
	quoted := make([]string, len(args))
	for i, arg := range args {
		// OpenSSH expands percent tokens even inside shell quotes. All values
		// here are literal arguments, never OpenSSH substitution templates.
		quoted[i] = core.ShellQuote(strings.ReplaceAll(arg, "%", "%%"))
	}
	target := core.SSHTarget{
		User:           user,
		Host:           claim.LeaseID,
		SSHHostKey:     hostKey,
		Key:            key,
		KnownHostsFile: filepath.Join(filepath.Dir(key), "known_hosts"),
		HostKeyAlias:   claim.LeaseID,
		Port:           port,
		TargetOS:       core.TargetLinux,
		NetworkKind:    core.NetworkPublic,
		SSHConfigProxy: true,
		ProxyCommand:   strings.Join(quoted, " "),
		ChildEnv:       childEnv,
		// Multiplex only within the exact Kubernetes runtime and pinned endpoint.
		// A fresh connection still passes through the identity-checking proxy.
		ControlScope: strings.Join([]string{claim.ProviderScope, claim.Labels[claimLabelClaimUID],
			claim.Labels[claimLabelSSHSandboxUID], claim.Labels[claimLabelSSHPodUID],
			claim.Labels[claimLabelSSHContainerID], claim.Labels[claimLabelExpiresAt]}, "\x00"),
		ReadyCheck: "command -v bash >/dev/null && command -v git >/dev/null && command -v rsync >/dev/null && command -v tar >/dev/null",
	}
	for _, label := range []string{claimLabelClaimUID, claimLabelSSHSandboxUID, claimLabelSSHPodUID, claimLabelSSHContainerID} {
		if claim.Labels[label] == "" {
			target.NoControlMaster = true
			break
		}
	}
	return target, nil
}

func (b *backend) sshProxyArgs(executable, leaseID string) ([]string, map[string]string) {
	values := b.cfg.AgentSandbox
	kubeconfig := expandHomePath(values.Kubeconfig)
	var childEnv map[string]string
	if kubeconfig == "" {
		identity := effectiveKubeconfigIdentity(values)
		if len(filepath.SplitList(identity)) == 1 && filepath.IsAbs(identity) {
			kubeconfig = identity
		} else {
			// kubectl's --kubeconfig is a single file, whereas KUBECONFIG may
			// merge several. Preserve that list without collapsing its identity.
			childEnv = map[string]string{"KUBECONFIG": identity}
		}
	}
	args := []string{executable, "__provider-ssh-proxy", sshProviderName, leaseID}
	for _, flag := range []struct{ name, value string }{
		{"kubectl", values.Kubectl},
		{"kubeconfig", kubeconfig},
		{"context", values.Context},
		{"namespace", values.Namespace},
		{"warm-pool", values.WarmPool},
		// Keep the configured selector, not the resolved container name: the
		// latter would change an implicit-container claim's provider scope.
		{"container", values.Container},
		{"workdir", values.Workdir},
	} {
		args = append(args, "--agent-sandbox-"+flag.name+"="+flag.value)
	}
	return args, childEnv
}

func (b *sshLeaseBackend) ProxySSH(ctx context.Context, identifier string, input io.Reader, output, stderr io.Writer) error {
	// OpenSSH sends SIGHUP to its ProxyCommand without waiting. Handle it
	// through cancellation so kubectl is stopped and reaped, rather than
	// letting the Go process exit abruptly with a live forwarding child.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGHUP)
	defer stop()
	lifecycle := b.lifecycle
	claim, err := resolveLocalClaim(lifecycle.cfg, identifier)
	if err != nil {
		return err
	}
	if claim.Provider != sshProviderName {
		return fmt.Errorf("lease %s does not belong to %s", claim.LeaseID, sshProviderName)
	}
	if err := authorizeClaimScope(lifecycle.cfg, claim); err != nil {
		return err
	}
	port := claim.Labels[claimLabelSSHPort]
	if !validSSHBootstrapPort(port) {
		return fmt.Errorf("agent-sandbox-ssh lease %s has no valid pinned SSH port; prepare the lease again", claim.LeaseID)
	}
	if claimTTLExpired(claim, lifecycle.now()) {
		return fmt.Errorf("agent-sandbox-ssh lease %s has expired", claim.LeaseID)
	}
	if expiry := claim.Labels[claimLabelExpiresAt]; expiry != "" {
		deadline, err := time.Parse(time.RFC3339, expiry)
		if err != nil {
			return fmt.Errorf("invalid SSH lease expiry: %w", err)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	// A proxy cannot finish recovery or bootstrap: that would mutate local
	// state while a run holds its operation lock. Require an already pinned UID.
	identity, err := claimIdentityFromLocalClaim(claim)
	if err != nil {
		return err
	}
	if identity.ProviderScope == "" {
		identity.ProviderScope = claimScope(lifecycle.cfg)
	}
	client, err := lifecycle.newClient(ctx, lifecycle.cfg, lifecycle.rt)
	if err != nil {
		return err
	}
	// This lookup validates the pinned claim UID, ownership, pool and TTL,
	// then establishes the complete Sandbox/pod/container binding immediately
	// before forwarding. Pending-UID recovery is deliberately not supported.
	ready, err := sandboxReadinessOnce(ctx, client, lifecycle.cfg.AgentSandbox.Namespace, claimNameFromLocalClaim(claim), identity)
	if err != nil {
		return err
	}
	if err := validateSSHRuntime(claim, ready); err != nil {
		return err
	}
	if claimTTLExpired(claim, lifecycle.now()) {
		return fmt.Errorf("agent-sandbox-ssh lease %s has expired", claim.LeaseID)
	}
	checkIdentity := func() error {
		if claimTTLExpired(claim, lifecycle.now()) {
			return fmt.Errorf("agent-sandbox-ssh lease %s has expired", claim.LeaseID)
		}
		return revalidateSandboxReadiness(ctx, client, lifecycle.cfg.AgentSandbox.Namespace, ready)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := checkIdentity(); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	err = lifecycle.forwardSSH(ctx, ready.PodName, port, input, output, stderr, checkIdentity)
	cause := context.Cause(ctx)
	cancel(nil)
	<-monitorDone
	return errors.Join(err, cause)
}

// Probe the actual authenticated SSH endpoint, without running a remote command,
// bootstrapping, or rewriting local trust. Pod readiness alone is insufficient.
func (b *backend) probeSSH(ctx context.Context, client kubernetesClient, ready sandboxReadiness, claim LeaseClaim) (resultErr error) {
	if err := validateSSHRuntime(claim, ready); err != nil {
		return err
	}
	target, err := b.sshTarget(claim)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(target.Key)
	if err != nil {
		return err
	}
	signer, err := xssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("read lease SSH authentication key: %w", err)
	}
	hostKey, _, _, _, err := xssh.ParseAuthorizedKey([]byte(target.SSHHostKey))
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, sshProxyReadyTimeout)
	defer cancel()
	local, proxy := net.Pipe()
	stop := context.AfterFunc(probeCtx, func() { local.Close(); proxy.Close() })
	defer stop()
	done := make(chan error, 1)
	check := func() error { return revalidateSandboxReadiness(probeCtx, client, b.cfg.AgentSandbox.Namespace, ready) }
	go func() {
		err := b.forwardSSH(probeCtx, ready.PodName, target.Port, proxy, proxy, io.Discard, check)
		proxy.Close()
		done <- err
	}()
	defer func() {
		cancel()
		local.Close()
		proxy.Close()
		forwardErr := <-done
		if resultErr != nil && forwardErr != nil && !errors.Is(forwardErr, context.Canceled) {
			resultErr = errors.Join(resultErr, forwardErr)
		}
	}()
	conn, _, _, err := xssh.NewClientConn(local, claim.LeaseID, &xssh.ClientConfig{
		User:            target.User,
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(signer)},
		HostKeyCallback: xssh.FixedHostKey(hostKey),
	})
	if err != nil {
		return fmt.Errorf("agent-sandbox-ssh endpoint unavailable: %w", err)
	}
	conn.Close()
	return check()
}

func (b *backend) sshHealth(ctx context.Context, claim LeaseClaim) error {
	identity, err := claimIdentityFromLocalClaim(claim)
	if err != nil {
		return err
	}
	if identity.ProviderScope == "" {
		identity.ProviderScope = claimScope(b.cfg)
	}
	client, err := b.client(ctx)
	if err != nil {
		return err
	}
	ready, err := sandboxReadinessOnce(ctx, client, b.cfg.AgentSandbox.Namespace, claimNameFromLocalClaim(claim), identity)
	if err != nil {
		return err
	}
	return b.probeSSH(ctx, client, ready, claim)
}

func (b *backend) forwardSSH(ctx context.Context, pod, remotePort string, input io.Reader, output, stderr io.Writer, checkIdentity func() error) error {
	if b.rt.Exec == nil {
		return errors.New("agent-sandbox-ssh proxy requires a command runner")
	}
	if stderr == nil {
		stderr = io.Discard
	}
	args := make([]string, 0, 8)
	if kubeconfig := expandHomePath(b.cfg.AgentSandbox.Kubeconfig); kubeconfig != "" {
		args = append(args, "--kubeconfig="+kubeconfig)
	}
	args = append(args,
		"--context="+b.cfg.AgentSandbox.Context,
		"--namespace="+b.cfg.AgentSandbox.Namespace,
		"port-forward", "--address=127.0.0.1", "pod/"+pod, ":"+remotePort,
	)
	processCtx, cancel := context.WithCancel(ctx)
	ports := make(chan string, 1)
	parser := &sshForwardOutput{ports: ports, remotePort: remotePort}
	done := make(chan error, 1)
	go func() {
		result, err := b.rt.Exec.Run(processCtx, LocalCommandRequest{
			Name:                 b.cfg.AgentSandbox.Kubectl,
			Args:                 args,
			Stdout:               parser,
			Stderr:               stderr,
			DisableOutputCapture: true,
			CancelGracePeriod:    time.Second,
		})
		if err == nil && result.ExitCode != 0 {
			err = fmt.Errorf("exit status %d", result.ExitCode)
		}
		done <- err
	}()
	processExited := false
	defer func() {
		cancel()
		if !processExited {
			<-done // Run joins the canceled kubectl; never leave a subprocess behind.
		}
	}()
	timer := time.NewTimer(sshProxyReadyTimeout)
	defer timer.Stop()
	var port string
	select {
	case port = <-ports:
	case err := <-done:
		processExited = true
		return sshForwardExitError("before opening a local port", err)
	case <-timer.C:
		return errors.New("timed out waiting for agent-sandbox-ssh kubectl port-forward")
	case <-ctx.Done():
		return ctx.Err()
	}
	// A pod name can be recycled while kubectl connects. Check again before
	// exposing its stream; the SSH host-key pin also rejects a replacement.
	if err := checkIdentity(); err != nil {
		return err
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, sshProxyReadyTimeout)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort("127.0.0.1", port))
	dialCancel()
	if err != nil {
		return fmt.Errorf("connect to agent-sandbox-ssh forwarded port: %w", err)
	}
	defer conn.Close()
	processExited, err = copySSHProxyStreams(ctx, conn, input, output, done)
	return err
}

func sshForwardExitError(when string, err error) error {
	if err == nil {
		return fmt.Errorf("agent-sandbox-ssh kubectl port-forward exited %s", when)
	}
	return fmt.Errorf("agent-sandbox-ssh kubectl port-forward exited %s: %w", when, err)
}

// kubectl writes readiness to stdout. Retain at most one bounded line, not
// arbitrary command output, and never copy diagnostics into the SSH stream.
type sshForwardOutput struct {
	ports       chan<- string
	remotePort  string
	line        []byte
	discardLine bool
}

func (w *sshForwardOutput) Write(p []byte) (int, error) {
	for _, c := range p {
		if c == '\n' {
			if !w.discardLine {
				if port, ok := parseSSHForwardPort(string(w.line), w.remotePort); ok {
					select {
					case w.ports <- port:
					default:
					}
				}
			}
			w.line = w.line[:0]
			w.discardLine = false
		} else if !w.discardLine {
			if len(w.line) == sshProxyOutputLineLimit {
				w.line = w.line[:0]
				w.discardLine = true
			} else {
				w.line = append(w.line, c)
			}
		}
	}
	return len(p), nil
}

func parseSSHForwardPort(line, remotePort string) (string, bool) {
	port, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "Forwarding from 127.0.0.1:")
	if !ok {
		return "", false
	}
	port, ok = strings.CutSuffix(port, " -> "+remotePort)
	if !ok || port == "" {
		return "", false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return strconv.Itoa(n), true
}

func copySSHProxyStreams(ctx context.Context, conn net.Conn, input io.Reader, output io.Writer, done <-chan error) (bool, error) {
	copied := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, input)
		copied <- err
	}()
	go func() {
		_, err := io.Copy(output, conn)
		copied <- err
	}()
	select {
	case err := <-copied:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return false, fmt.Errorf("agent-sandbox-ssh proxy stream: %w", err)
		}
		// Both directions carry the SSH transport itself, not remote command
		// stdin/stdout. EOF in either means the SSH connection is finished.
		// kubectl does not propagate TCP half-close reliably, so waiting for
		// remote EOF after client EOF could leave the forwarding child alive.
		return false, nil
	case err := <-done:
		return true, sshForwardExitError("during SSH forwarding", err)
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

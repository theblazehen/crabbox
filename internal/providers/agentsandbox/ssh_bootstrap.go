package agentsandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	core "github.com/openclaw/crabbox/internal/cli"
	"golang.org/x/crypto/ssh"
)

const (
	claimLabelSSHUser        = "ssh_user"
	claimLabelSSHHostKey     = "ssh_host_key"
	claimLabelSSHSandboxUID  = "ssh_sandbox_uid"
	claimLabelSSHPodUID      = "ssh_pod_uid"
	claimLabelSSHContainerID = "ssh_container_id"
	sshUserMarker            = "CRABBOX_SSH_USER="
	sshHostKeyMarker         = "CRABBOX_SSH_HOST_KEY="
	sshPortMarker            = "CRABBOX_SSH_PORT="
	sshSeedInitializer       = "/opt/crabbox-seed/initialize"
)

// Compatibility discovery reads the image executable without running it. A
// missing seed or unsupported checksum utility is an explicit successful probe;
// failures of Kubernetes exec itself must never look like seed absence.
const sshSeedProbe = `if [ -f "$1" ] && [ -x "$1" ] && command -v sha256sum >/dev/null 2>&1; then
  if digest=$(sha256sum "$1" 2>/dev/null); then
    printf '%s\n' "$digest"
    exit 0
  fi
fi
printf 'CRABBOX_SEED_UNAVAILABLE\n'
`

type sshBootstrapInfo struct {
	User    string
	HostKey string
	Port    string
}

type sshInitializationRequest struct {
	LeaseID   string `json:"lease_id"`
	PublicKey string `json:"public_key"`
}

func (b *backend) prepareSSH(ctx context.Context, client kubernetesClient, ready sandboxReadiness, claim LeaseClaim) (LeaseClaim, error) {
	_, publicKey, err := core.EnsureTestboxKey(claim.LeaseID)
	if err != nil {
		return LeaseClaim{}, err
	}
	request, err := sshInitializationInput(claim.LeaseID, publicKey)
	if err != nil {
		return LeaseClaim{}, err
	}
	execCtx, cancel := b.execContext(ctx)
	defer cancel()
	var info sshBootstrapInfo
	for attempt := 0; ; attempt++ {
		if ready.ContainerID == "" {
			return LeaseClaim{}, fmt.Errorf("%w: agent-sandbox-ssh pod %s has no running container identity", errNotReady, ready.PodName)
		}
		info, err = b.initializeSSH(execCtx, client, ready, request)
		if err == nil {
			err = revalidateSandboxReadiness(execCtx, client, b.cfg.AgentSandbox.Namespace, ready)
		}
		if err == nil {
			break
		}
		if attempt == 2 || execCtx.Err() != nil {
			return LeaseClaim{}, err
		}
		// Retry only an endpoint replacement authenticated under the same
		// immutable claim. Never replay a workload or accept an SSH-presented key.
		current, checkErr := b.waitForClaimReadiness(execCtx, client, ready.ClaimName, ready.identity)
		if checkErr != nil || sameSSHRuntime(ready, current) {
			return LeaseClaim{}, errors.Join(err, checkErr)
		}
		ready = current
	}
	labels := claimReadinessLabels(claim.Labels, ready)
	labels[claimLabelSSHUser] = info.User
	labels[claimLabelSSHHostKey] = info.HostKey
	labels[claimLabelSSHPort] = info.Port
	labels[claimLabelSSHSandboxUID] = ready.SandboxUID
	labels[claimLabelSSHPodUID] = ready.PodUID
	labels[claimLabelSSHContainerID] = ready.ContainerID
	updated, err := updateLeaseClaimLabelsIfUnchanged(claim.LeaseID, claim, labels)
	if err != nil {
		return LeaseClaim{}, fmt.Errorf("agent-sandbox-ssh publish SSH identity: %w", err)
	}
	target, err := b.sshTarget(updated)
	if err != nil {
		return LeaseClaim{}, err
	}
	if err := core.PrepareLeaseSSHTrust(&target, claim.LeaseID); err != nil {
		return LeaseClaim{}, fmt.Errorf("agent-sandbox-ssh prepare pinned host trust: %w", err)
	}
	return updated, nil
}

func sameSSHRuntime(a, b sandboxReadiness) bool {
	return a.SandboxUID == b.SandboxUID && a.PodUID == b.PodUID && a.Container == b.Container && a.ContainerID == b.ContainerID
}

func validateSSHRuntime(claim LeaseClaim, ready sandboxReadiness) error {
	if ready.ContainerID == "" || claim.Labels[claimLabelSSHSandboxUID] != ready.SandboxUID || claim.Labels[claimLabelSSHPodUID] != ready.PodUID || claim.Labels[claimLabelSSHContainerID] != ready.ContainerID {
		return fmt.Errorf("agent-sandbox-ssh lease %s endpoint is unverified or its container changed; prepare the lease again through Kubernetes", claim.LeaseID)
	}
	return nil
}

// Kubernetes exec is the authenticated bootstrap channel. Only the lease public
// key crosses it; the client private key never leaves the local machine.
func (b *backend) initializeSSH(ctx context.Context, client kubernetesClient, ready sandboxReadiness, input []byte) (info sshBootstrapInfo, resultErr error) {
	var architecture bytes.Buffer
	if err := b.execPod(ctx, client, ready, podExecRequest{
		Command: []string{"uname", "-m"}, Stdout: &architecture, Stderr: b.rt.Stderr,
	}); err != nil {
		return info, fmt.Errorf("agent-sandbox-ssh identify Linux architecture: %w", err)
	}
	payload, err := openSSHInitializer(strings.TrimSpace(architecture.String()))
	if err != nil {
		return info, err
	}
	defer payload.Close()
	digest, err := sshInitializerSHA256()
	if err != nil {
		return info, err
	}
	var probe bytes.Buffer
	if err := b.execPod(ctx, client, ready, podExecRequest{
		Command: []string{"sh", "-c", sshSeedProbe, "crabbox-seed-probe", sshSeedInitializer}, Stdout: &probe, Stderr: b.rt.Stderr,
	}); err != nil {
		return info, fmt.Errorf("agent-sandbox-ssh probe seeded initializer: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return info, err
	}
	fields := strings.Fields(probe.String())
	if len(fields) == 2 && fields[0] == digest && fields[1] == sshSeedInitializer {
		return b.executeSSHInitializer(ctx, client, ready, sshSeedInitializer, input)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return info, fmt.Errorf("create initializer upload name: %w", err)
	}
	dir := "/tmp/crabbox-init-" + hex.EncodeToString(nonce[:])
	path := dir + "/initialize"
	// mkdir must create a new private directory. Never follow or reuse a path
	// supplied by the image, even if it is a dangling symlink.
	remove := "rm -f " + shellQuote(path) + " && rmdir " + shellQuote(dir)
	upload := "set -eu; umask 077; mkdir " + shellQuote(dir) + "; trap " + shellQuote(remove) + " 0; cat > " + shellQuote(path) + "; chmod 700 " + shellQuote(path) + "; trap - 0"
	if err := b.execPod(ctx, client, ready, podExecRequest{
		Command: []string{"sh", "-c", upload}, Stdin: payload, Stdout: io.Discard, Stderr: b.rt.Stderr,
	}); err != nil {
		return info, fmt.Errorf("agent-sandbox-ssh upload static initializer (requires sh, uname, mkdir, cat, chmod and writable /tmp): %w", err)
	}
	defer func() {
		cleanupCtx, cancel := b.cleanupContext(ctx)
		defer cancel()
		err := b.execPod(cleanupCtx, client, ready, podExecRequest{
			Command: []string{"sh", "-c", remove},
			Stdout:  io.Discard, Stderr: b.rt.Stderr,
		})
		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary SSH initializer: %w", err))
		}
	}()
	return b.executeSSHInitializer(ctx, client, ready, path, input)
}

func (b *backend) executeSSHInitializer(ctx context.Context, client kubernetesClient, ready sandboxReadiness, path string, input []byte) (sshBootstrapInfo, error) {
	var output bytes.Buffer
	if err := b.execPod(ctx, client, ready, podExecRequest{
		Command: []string{path}, Stdin: bytes.NewReader(input), Stdout: &output, Stderr: b.rt.Stderr,
	}); err != nil {
		return sshBootstrapInfo{}, fmt.Errorf("agent-sandbox-ssh additive initialization failed: %w", err)
	}
	return parseSSHBootstrapOutput(output.String())
}

func parseSSHBootstrapOutput(output string) (sshBootstrapInfo, error) {
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], sshUserMarker) || !strings.HasPrefix(lines[1], sshHostKeyMarker) || !strings.HasPrefix(lines[2], sshPortMarker) {
		return sshBootstrapInfo{}, fmt.Errorf("agent-sandbox-ssh initializer returned unexpected or duplicate output")
	}
	info := sshBootstrapInfo{User: strings.TrimPrefix(lines[0], sshUserMarker), HostKey: strings.TrimPrefix(lines[1], sshHostKeyMarker), Port: strings.TrimPrefix(lines[2], sshPortMarker)}
	if info.User != "root" {
		return sshBootstrapInfo{}, fmt.Errorf("agent-sandbox-ssh initializer did not return the root SSH user")
	}
	if err := validateBootstrapPublicKey(info.HostKey); err != nil {
		return sshBootstrapInfo{}, err
	}
	if !validSSHBootstrapPort(info.Port) {
		return sshBootstrapInfo{}, fmt.Errorf("agent-sandbox-ssh initializer returned an invalid SSH port")
	}
	return info, nil
}

func validateBootstrapPublicKey(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("agent-sandbox-ssh invalid SSH public key")
	}
	_, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || len(options) != 0 || strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("agent-sandbox-ssh invalid SSH public key")
	}
	return nil
}

func sshInitializationInput(leaseID, publicKey string) ([]byte, error) {
	if leaseID == "" || len(leaseID) > 128 || strings.Trim(leaseID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
		return nil, fmt.Errorf("agent-sandbox-ssh invalid lease ID")
	}
	publicKey = strings.TrimSpace(publicKey)
	if err := validateBootstrapPublicKey(publicKey); err != nil {
		return nil, err
	}
	return json.Marshal(sshInitializationRequest{LeaseID: leaseID, PublicKey: publicKey})
}

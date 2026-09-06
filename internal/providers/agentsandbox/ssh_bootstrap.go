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
	claimLabelSSHUser    = "ssh_user"
	claimLabelSSHHostKey = "ssh_host_key"
	sshUserMarker        = "CRABBOX_SSH_USER="
	sshHostKeyMarker     = "CRABBOX_SSH_HOST_KEY="
	sshPortMarker        = "CRABBOX_SSH_PORT="
)

type sshBootstrapInfo struct {
	User    string
	HostKey string
	Port    string
}

type sshInitializationRequest struct {
	LeaseID         string `json:"lease_id"`
	PublicKey       string `json:"public_key"`
	ExpectedHostKey string `json:"expected_host_key"`
	ExpectedPort    string `json:"expected_port"`
}

func (b *backend) prepareSSH(ctx context.Context, client kubernetesClient, ready sandboxReadiness, claim LeaseClaim) (LeaseClaim, error) {
	oldUser, oldKey, oldPort := claim.Labels[claimLabelSSHUser], claim.Labels[claimLabelSSHHostKey], claim.Labels[claimLabelSSHPort]
	if oldUser != "" || oldKey != "" || oldPort != "" {
		if oldUser != "root" || oldKey == "" || !validSSHBootstrapPort(oldPort) {
			return LeaseClaim{}, fmt.Errorf("agent-sandbox-ssh lease %s has incomplete SSH identity metadata; acquire a new lease", claim.LeaseID)
		}
	}
	_, publicKey, err := core.EnsureTestboxKey(claim.LeaseID)
	if err != nil {
		return LeaseClaim{}, err
	}
	request, err := sshInitializationInput(claim.LeaseID, publicKey, oldKey, oldPort)
	if err != nil {
		return LeaseClaim{}, err
	}
	execCtx, cancel := b.execContext(ctx)
	defer cancel()
	info, err := b.initializeSSH(execCtx, client, ready, request)
	if err != nil {
		return LeaseClaim{}, err
	}
	if oldKey != "" && (oldKey != info.HostKey || oldPort != info.Port) {
		return LeaseClaim{}, fmt.Errorf("agent-sandbox-ssh lease %s SSH identity or port changed; refusing to replace its pinned endpoint", claim.LeaseID)
	}
	if err := revalidateSandboxReadiness(execCtx, client, b.cfg.AgentSandbox.Namespace, ready); err != nil {
		return LeaseClaim{}, err
	}
	labels := cloneStringMap(claim.Labels)
	labels[claimLabelSSHUser] = info.User
	labels[claimLabelSSHHostKey] = info.HostKey
	labels[claimLabelSSHPort] = info.Port
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
	var output bytes.Buffer
	if err := b.execPod(ctx, client, ready, podExecRequest{
		Command: []string{path}, Stdin: bytes.NewReader(input), Stdout: &output, Stderr: b.rt.Stderr,
	}); err != nil {
		return info, fmt.Errorf("agent-sandbox-ssh additive initialization failed: %w", err)
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

func sshInitializationInput(leaseID, publicKey, expectedHostKey, expectedPort string) ([]byte, error) {
	if leaseID == "" || len(leaseID) > 128 || strings.Trim(leaseID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
		return nil, fmt.Errorf("agent-sandbox-ssh invalid lease ID")
	}
	publicKey = strings.TrimSpace(publicKey)
	if err := validateBootstrapPublicKey(publicKey); err != nil {
		return nil, err
	}
	if expectedHostKey != "" {
		if err := validateBootstrapPublicKey(expectedHostKey); err != nil {
			return nil, err
		}
	}
	if (expectedHostKey == "") != (expectedPort == "") || (expectedPort != "" && !validSSHBootstrapPort(expectedPort)) {
		return nil, fmt.Errorf("agent-sandbox-ssh incomplete pinned initializer endpoint")
	}
	return json.Marshal(sshInitializationRequest{LeaseID: leaseID, PublicKey: publicKey, ExpectedHostKey: expectedHostKey, ExpectedPort: expectedPort})
}

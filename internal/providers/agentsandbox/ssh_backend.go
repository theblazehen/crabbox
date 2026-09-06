package agentsandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	core "github.com/openclaw/crabbox/internal/cli"
)

// Composition deliberately excludes the archive provider's Run and Warmup.
type sshLeaseBackend struct {
	lifecycle *backend
}

var _ core.SSHLeaseBackend = (*sshLeaseBackend)(nil)
var _ core.SSHRunActivityBackend = (*sshLeaseBackend)(nil)
var _ core.ReleaseLeaseOutcomeBackend = (*sshLeaseBackend)(nil)

func (b *sshLeaseBackend) Spec() ProviderSpec { return b.lifecycle.Spec() }
func (b *sshLeaseBackend) Doctor(ctx context.Context, req DoctorRequest) (DoctorResult, error) {
	return b.lifecycle.Doctor(ctx, req)
}
func (b *sshLeaseBackend) List(ctx context.Context, req ListRequest) ([]LeaseView, error) {
	return b.lifecycle.List(ctx, req)
}
func (b *sshLeaseBackend) Status(ctx context.Context, req StatusRequest) (StatusView, error) {
	return b.lifecycle.Status(ctx, req)
}
func (b *sshLeaseBackend) Cleanup(ctx context.Context, req CleanupRequest) error {
	return b.lifecycle.Cleanup(ctx, req)
}

func sshLeaseFromClaim(claim LeaseClaim) core.LeaseTarget {
	labels := cloneStringMap(claim.Labels)
	labels["provider"] = sshProviderName
	labels["lease"] = claim.LeaseID
	labels["slug"] = claim.Slug
	labels["pond"] = claim.Pond
	name := claimNameFromLocalClaim(claim)
	server := Server{Provider: sshProviderName, CloudID: name, ImmutableID: labels[claimLabelClaimUID], Name: name, Status: labels["state"], Labels: labels}
	return core.LeaseTarget{LeaseID: claim.LeaseID, Server: server}
}

func (b *sshLeaseBackend) Acquire(ctx context.Context, req core.AcquireRequest) (core.LeaseTarget, error) {
	if req.RequestedLeaseID != "" || req.RequestedCheckpointID != "" {
		return core.LeaseTarget{}, exit(2, "provider=%s does not support fixed lease IDs or checkpoints", sshProviderName)
	}
	lifecycle := b.lifecycle
	client, err := lifecycle.client(ctx)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	var observed func(LeaseClaim) error
	if req.OnAcquired != nil {
		observed = func(claim LeaseClaim) error { return req.OnAcquired(sshLeaseFromClaim(claim)) }
	}
	leaseID, name, _, ready, claim, unlock, err := lifecycle.createClaim(ctx, client, req.RequestedSlug, req.Repo, req.Reclaim, observed)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	defer unlock()
	lease, err := b.prepare(ctx, client, ready, claim)
	if err == nil {
		return lease, nil
	}
	// A failed acquisition is not a usable retained lease, even with --keep.
	// Cleanup failure preserves the claim and credentials for explicit recovery.
	cleanupCtx, cancel := lifecycle.cleanupContext(ctx)
	defer cancel()
	current, readErr := resolveLocalClaim(lifecycle.cfg, leaseID)
	if readErr != nil {
		return core.LeaseTarget{}, errors.Join(err, readErr)
	}
	if current.Labels[claimLabelClaimUID] != claim.Labels[claimLabelClaimUID] {
		return core.LeaseTarget{}, errors.Join(err, exit(4, "lease %s changed during SSH acquisition; recovery claim retained", leaseID))
	}
	if terminal, cleanupErr := lifecycle.deleteOwnedClaim(cleanupCtx, client, current, leaseID, name, false); cleanupErr != nil {
		if terminal {
			return core.LeaseTarget{}, errors.Join(err, fmt.Errorf("SSH bootstrap rollback deleted claim %s but local finalization failed: %w", name, cleanupErr))
		}
		return core.LeaseTarget{}, errors.Join(err, fmt.Errorf("SSH bootstrap rollback failed; retain lease %s for %s %s: %w", leaseID, agentSandboxRecoveryCommand(lifecycle.cfg, "stop"), shellQuote(leaseID), cleanupErr))
	}
	return core.LeaseTarget{}, err
}

func (b *sshLeaseBackend) prepare(ctx context.Context, client kubernetesClient, ready sandboxReadiness, claim LeaseClaim) (core.LeaseTarget, error) {
	updated, err := b.lifecycle.prepareSSH(ctx, client, ready, claim)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	if claimTTLExpired(updated, b.lifecycle.now().UTC()) {
		return core.LeaseTarget{}, exit(4, "agent-sandbox claim %s reached its TTL expiry during SSH preparation", claim.LeaseID)
	}
	lease := sshLeaseFromClaim(updated)
	lease.SSH, err = b.lifecycle.sshTarget(updated)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	updated, err = core.UpdateLeaseClaimEndpointIfUnchangedWithProviderMetadata(claim.LeaseID, updated, lease.Server, lease.SSH)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	core.SetServerLeaseClaimSnapshot(&lease.Server, updated, true)
	return lease, nil
}

// Ordinary resolution owns its short operation fence and uses compare-and-swap
// publication. It must not opt into RunLeaseClaimResolver: bootstrap publishes
// host keys and cannot execute while core already holds the claim lock.
func (b *sshLeaseBackend) Resolve(ctx context.Context, req core.ResolveRequest) (core.LeaseTarget, error) {
	lifecycle := b.lifecycle
	claim, err := resolveLocalClaim(lifecycle.cfg, req.ID)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	readOnly := req.StatusOnly || req.NoLocalStateMutations || req.ReleaseOnly
	if !readOnly {
		unlock, err := lockAgentSandboxLeaseOperation(ctx, claim.LeaseID)
		if err != nil {
			return core.LeaseTarget{}, err
		}
		defer unlock()
		claim, err = resolveLocalClaim(lifecycle.cfg, claim.LeaseID)
		if err != nil {
			return core.LeaseTarget{}, err
		}
	}
	if err := authorizeClaimScope(lifecycle.cfg, claim); err != nil {
		return core.LeaseTarget{}, err
	}
	if err := authorizeAgentSandboxRepoClaim(claim, req.Repo.Root, req.Reclaim); err != nil {
		return core.LeaseTarget{}, err
	}
	lease := sshLeaseFromClaim(claim)
	if err := core.ValidateLeaseTargetProviderIdentity(lease, req.ExpectedProviderIdentity); err != nil {
		return core.LeaseTarget{}, err
	}
	client, err := lifecycle.client(ctx)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	name := claimNameFromLocalClaim(claim)
	live, err := client.Get(ctx, sandboxClaimGVR(), lifecycle.cfg.AgentSandbox.Namespace, name)
	if err != nil {
		if isNotFound(err) && (req.StatusOnly || req.ReleaseOnly) {
			lease.Server.Status = "missing-or-inaccessible"
			lease.Server.Labels["state"] = lease.Server.Status
			return lease, nil
		}
		return core.LeaseTarget{}, err
	}
	claim, identity, err := lifecycle.claimIdentityForLiveClaim(claim, live, !readOnly)
	if err != nil {
		return core.LeaseTarget{}, err
	}
	lease = sshLeaseFromClaim(claim)
	if req.ReleaseOnly {
		core.SetServerLeaseClaimSnapshot(&lease.Server, claim, true)
		return lease, nil
	}
	if expired, reason := sandboxClaimExpired(claim, live, lifecycle.now().UTC()); expired {
		if !req.StatusOnly {
			return core.LeaseTarget{}, exit(4, "agent-sandbox lease %s expired: %s", claim.LeaseID, reason)
		}
		lease.Server.Status = "expired"
		lease.Server.Labels["state"] = "expired"
		return lease, nil
	}
	var ready sandboxReadiness
	if readOnly {
		ready, err = sandboxReadinessOnce(ctx, client, lifecycle.cfg.AgentSandbox.Namespace, name, identity)
	} else {
		ready, err = lifecycle.waitForClaimReadiness(ctx, client, name, identity)
	}
	if err != nil {
		if req.StatusOnly && (errors.Is(err, errNotReady) || isNotFound(err) || isResourceTerminalError(err) || isSandboxExpiredError(err)) {
			lease.Server.Status = "not-ready"
			lease.Server.Labels["state"] = lease.Server.Status
			return lease, nil
		}
		return core.LeaseTarget{}, err
	}
	if readOnly {
		lease.SSH, err = lifecycle.sshTarget(claim)
		if err != nil && !req.StatusOnly {
			return core.LeaseTarget{}, err
		}
		core.SetServerLeaseClaimSnapshot(&lease.Server, claim, true)
		return lease, nil
	}
	claim, err = updateLeaseClaimLabelsIfUnchanged(claim.LeaseID, claim, claimReadinessLabels(claim.Labels, ready))
	if err != nil {
		return core.LeaseTarget{}, err
	}
	if req.Reclaim && req.Repo.Root != "" {
		claim, err = core.ClaimLeaseForRepoProviderScopePondIfUnchanged(claim.LeaseID, claim.Slug, sshProviderName, claimScope(lifecycle.cfg), claim.Pond, req.Repo.Root, lifecycle.cfg.IdleTimeout, true, claim, true)
		if err != nil {
			return core.LeaseTarget{}, err
		}
	}
	return b.prepare(ctx, client, ready, claim)
}

func (b *sshLeaseBackend) currentClaimForTarget(lease core.LeaseTarget) (LeaseClaim, error) {
	claim, err := resolveLocalClaim(b.lifecycle.cfg, lease.LeaseID)
	if err != nil {
		return LeaseClaim{}, err
	}
	if err := authorizeClaimScope(b.lifecycle.cfg, claim); err != nil {
		return LeaseClaim{}, err
	}
	if lease.Server.CloudID != claimNameFromLocalClaim(claim) || strings.TrimSpace(lease.Server.Labels[claimLabelClaimUID]) != strings.TrimSpace(claim.Labels[claimLabelClaimUID]) {
		return LeaseClaim{}, errors.Join(core.ErrReleaseLeaseOwnershipChanged, exit(4, "agent-sandbox lease %s ownership changed", claim.LeaseID))
	}
	if previous, exists, attached := core.ServerLeaseClaimSnapshot(lease.Server); attached && (!exists || previous.RepoRoot != claim.RepoRoot || previous.ClaimedAt != claim.ClaimedAt) {
		return LeaseClaim{}, errors.Join(core.ErrReleaseLeaseOwnershipChanged, exit(4, "agent-sandbox lease %s repository ownership changed", claim.LeaseID))
	}
	return claim, nil
}

func (b *sshLeaseBackend) BeginSSHRunActivity(ctx context.Context, lease core.LeaseTarget) (func(), error) {
	unlock, err := lockAgentSandboxLeaseOperation(ctx, lease.LeaseID)
	if err != nil {
		return nil, err
	}
	claim, err := b.currentClaimForTarget(lease)
	if err == nil {
		var client kubernetesClient
		client, err = b.lifecycle.client(ctx)
		if err == nil {
			var identity claimIdentity
			identity, err = claimIdentityFromLocalClaim(claim)
			if err == nil {
				_, err = sandboxReadinessOnce(ctx, client, b.lifecycle.cfg.AgentSandbox.Namespace, claimNameFromLocalClaim(claim), identity)
			}
		}
		if err == nil && claimTTLExpired(claim, b.lifecycle.now().UTC()) {
			err = exit(4, "agent-sandbox lease %s reached its TTL expiry; command not run", claim.LeaseID)
		}
	}
	if err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

func (b *sshLeaseBackend) Touch(ctx context.Context, req core.TouchRequest) (core.Server, error) {
	if err := ctx.Err(); err != nil {
		return Server{}, err
	}
	claim, err := b.currentClaimForTarget(req.Lease)
	if err != nil {
		return Server{}, err
	}
	cfg := b.lifecycle.cfg
	if req.IdleTimeoutOverride != nil {
		cfg.IdleTimeout = *req.IdleTimeoutOverride
	} else if req.IdleTimeout > 0 {
		cfg.IdleTimeout = req.IdleTimeout
	}
	var updated LeaseClaim
	if claim.RepoRoot == "" {
		lease := sshLeaseFromClaim(claim)
		updated, err = core.ClaimLeaseTargetForConfigScopeIfUnchanged(claim.LeaseID, claim.Slug, cfg, claim.ProviderScope, lease.Server, req.Lease.SSH, cfg.IdleTimeout, claim, true)
	} else {
		updated, err = core.ClaimLeaseForRepoProviderScopePondIfUnchanged(claim.LeaseID, claim.Slug, sshProviderName, claim.ProviderScope, claim.Pond, claim.RepoRoot, cfg.IdleTimeout, false, claim, true)
	}
	if err != nil {
		return Server{}, err
	}
	labels := cloneStringMap(updated.Labels)
	if req.State != "" {
		labels["state"] = req.State
	}
	updated, err = updateLeaseClaimLabelsIfUnchanged(claim.LeaseID, updated, labels)
	if err != nil {
		return Server{}, err
	}
	server := sshLeaseFromClaim(updated).Server
	core.SetServerLeaseClaimSnapshot(&server, updated, true)
	return server, nil
}

func (b *sshLeaseBackend) ReleaseLeaseConnectionCleanupSafe() bool { return false }
func (b *sshLeaseBackend) ReleaseLeaseMessage(lease core.LeaseTarget) string {
	if !b.lifecycle.cfg.AgentSandbox.DeleteOnRelease {
		return fmt.Sprintf("retained lease=%s claim=%s because agentSandbox.deleteOnRelease=false", lease.LeaseID, lease.Server.Name)
	}
	return fmt.Sprintf("released lease=%s claim=%s", lease.LeaseID, lease.Server.Name)
}
func (b *sshLeaseBackend) RetainLeaseClaimAfterRelease(core.LeaseTarget) bool {
	return !b.lifecycle.cfg.AgentSandbox.DeleteOnRelease
}
func (b *sshLeaseBackend) ReleaseLease(ctx context.Context, req core.ReleaseLeaseRequest) error {
	_, err := b.ReleaseLeaseWithOutcome(ctx, req)
	return err
}
func (b *sshLeaseBackend) ReleaseLeaseWithOutcome(ctx context.Context, req core.ReleaseLeaseRequest) (core.ReleaseLeaseOutcome, error) {
	if req.CheckpointID != "" {
		return core.ReleaseLeaseOutcome{}, exit(2, "provider=%s does not support checkpoints", sshProviderName)
	}
	unlock, err := lockAgentSandboxLeaseOperation(ctx, req.Lease.LeaseID)
	if err != nil {
		return core.ReleaseLeaseOutcome{}, err
	}
	defer unlock()
	claim, err := b.currentClaimForTarget(req.Lease)
	if err != nil {
		return core.ReleaseLeaseOutcome{}, err
	}
	lease := sshLeaseFromClaim(claim)
	if err := core.ValidateLeaseTargetProviderIdentity(lease, req.ExpectedProviderIdentity); err != nil {
		return core.ReleaseLeaseOutcome{}, err
	}
	if !b.lifecycle.cfg.AgentSandbox.DeleteOnRelease {
		return core.ReleaseLeaseOutcome{}, nil
	}
	client, err := b.lifecycle.client(ctx)
	if err != nil {
		return core.ReleaseLeaseOutcome{}, err
	}
	name := claimNameFromLocalClaim(claim)
	live, err := client.Get(ctx, sandboxClaimGVR(), b.lifecycle.cfg.AgentSandbox.Namespace, name)
	if err != nil {
		if isNotFound(err) && b.lifecycle.cfg.AgentSandbox.ForgetMissing {
			err = b.lifecycle.removeLocalClaim(claim.LeaseID, claim)
			return core.ReleaseLeaseOutcome{Terminal: true}, err
		}
		return core.ReleaseLeaseOutcome{}, err
	}
	claim, _, err = b.lifecycle.claimIdentityForLiveClaim(claim, live, true)
	if err != nil {
		return core.ReleaseLeaseOutcome{}, err
	}
	if req.GuardedRemoteCleanup != nil {
		cleanupLease := req.Lease
		if cleanupLease.SSH.Host == "" {
			// Optional remote hygiene must not make a broken SSH bootstrap
			// prevent the UID-guarded Kubernetes release.
			cleanupLease.SSH, _ = b.lifecycle.sshTarget(claim)
		}
		if cleanupLease.SSH.Host != "" {
			req.GuardedRemoteCleanup(ctx, cleanupLease)
		}
	}
	terminal, err := b.lifecycle.deleteOwnedClaim(ctx, client, claim, claim.LeaseID, name, false)
	return core.ReleaseLeaseOutcome{Terminal: terminal}, err
}

package agentsandbox

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
)

func testSSHBackend(t *testing.T) (*sshLeaseBackend, *fakeKubernetesClient) {
	t.Helper()
	cfg := testAgentSandboxConfig(t)
	cfg.Provider = sshProviderName
	fake := readyFakeClient(cfg)
	lifecycle := testBackend(cfg, fake, nil, nil)
	lifecycle.spec = SSHProvider{}.Spec()
	return &sshLeaseBackend{lifecycle: lifecycle}, fake
}

func createSSHTestClaim(t *testing.T, b *sshLeaseBackend, fake *fakeKubernetesClient) LeaseClaim {
	t.Helper()
	_, _, _, _, claim, unlock, err := b.lifecycle.createClaim(context.Background(), fake, "ssh-lifecycle", Repo{Root: t.TempDir()}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	return claim
}

func TestSSHProviderKeepsSeparateScopeAndExecutionContract(t *testing.T) {
	b, fake := testSSHBackend(t)
	if _, ok := any(b).(core.DelegatedRunBackend); ok {
		t.Fatal("SSH adapter inherited archive execution")
	}
	claim := createSSHTestClaim(t, b, fake)
	cfg := b.lifecycle.cfg
	cfg.Provider = providerName
	if claim.Provider != sshProviderName || claim.ProviderScope == claimScope(cfg) {
		t.Fatalf("claim=%#v", claim)
	}
	if err := authorizeClaimScope(cfg, claim); err == nil {
		t.Fatal("archive provider accepted SSH claim")
	}
	if _, err := resolveLocalClaim(cfg, claim.LeaseID); err == nil {
		t.Fatal("archive provider resolved SSH lease")
	}
	live := fake.objects[sandboxClaimResource+"/"+cfg.AgentSandbox.Namespace+"/"+claimNameFromLocalClaim(claim)]
	if live.Metadata.Labels[labelProvider] != sshProviderName {
		t.Fatalf("labels=%#v", live.Metadata.Labels)
	}
	identity, err := claimIdentityFromLocalClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	live.Metadata.Labels[labelProvider] = providerName
	if err := validateClaimIdentity(live, identity); err == nil {
		t.Fatal("changed provider identity accepted")
	}
}

func TestSSHAcquireObserverRunsBeforeReadinessAndClaimPublication(t *testing.T) {
	b, fake := testSSHBackend(t)
	want := errors.New("caller rejected acquisition")
	called := false
	_, err := b.Acquire(context.Background(), core.AcquireRequest{RequestedSlug: "observer", OnAcquired: func(lease core.LeaseTarget) error {
		called = true
		if lease.Server.ImmutableID == "" || lease.Server.CloudID == "" {
			t.Fatalf("unbound acquisition: %#v", lease)
		}
		claim, err := readLeaseClaim(lease.LeaseID)
		if err != nil {
			t.Fatal(err)
		}
		if claim.LeaseID != "" {
			t.Fatal("claim published before acquisition observer")
		}
		if len(fake.execs) != 0 {
			t.Fatal("bootstrap ran before acquisition observer")
		}
		return want
	}})
	if !called || !errors.Is(err, want) || fake.deletes != 1 {
		t.Fatalf("called=%v err=%v deletes=%d", called, err, fake.deletes)
	}
	claims, err := listAgentSandboxLeaseClaims()
	if err != nil || len(claims) != 0 {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
}

func TestSSHAcquireRollbackFailurePreservesRecoveryClaim(t *testing.T) {
	b, fake := testSSHBackend(t)
	fake.deleteErrs = []error{errors.New("delete denied")}
	_, err := b.Acquire(context.Background(), core.AcquireRequest{RequestedSlug: "recovery", OnAcquired: func(core.LeaseTarget) error { return errors.New("reject") }})
	if err == nil || !strings.Contains(err.Error(), sshProviderName) {
		t.Fatalf("err=%v", err)
	}
	claims, err := listAgentSandboxLeaseClaims()
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if claims[0].Labels[claimLabelClaimUID] == "" || claims[0].Provider != sshProviderName {
		t.Fatalf("claim=%#v", claims[0])
	}
	if claims[0].RepoRoot != "" {
		t.Fatalf("recovery invented a repository owner: %q", claims[0].RepoRoot)
	}
	server, err := b.Touch(context.Background(), core.TouchRequest{Lease: sshLeaseFromClaim(claims[0]), State: "retained"})
	if err != nil || server.Labels["state"] != "retained" {
		t.Fatalf("touch unbound recovery lease: server=%#v err=%v", server, err)
	}
}

func TestSSHReadOnlyResolveNeverBootstrapsOrPublishes(t *testing.T) {
	b, fake := testSSHBackend(t)
	claim := createSSHTestClaim(t, b, fake)
	lease, err := b.Resolve(context.Background(), core.ResolveRequest{ID: claim.LeaseID, StatusOnly: true, NoLocalStateMutations: true})
	if err != nil {
		t.Fatal(err)
	}
	if lease.LeaseID != claim.LeaseID || len(fake.execs) != 0 {
		t.Fatalf("lease=%#v execs=%d", lease, len(fake.execs))
	}
	current, err := readLeaseClaim(claim.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(current, claim) {
		t.Fatal("status lookup rewrote claim")
	}
}

func TestSSHReleaseRetentionDoesNotDeleteOrClaimTerminalOutcome(t *testing.T) {
	b, fake := testSSHBackend(t)
	claim := createSSHTestClaim(t, b, fake)
	b.lifecycle.cfg.AgentSandbox.DeleteOnRelease = false
	outcome, err := b.ReleaseLeaseWithOutcome(context.Background(), core.ReleaseLeaseRequest{Lease: sshLeaseFromClaim(claim)})
	if err != nil || outcome.Terminal || fake.deletes != 0 {
		t.Fatalf("outcome=%#v err=%v deletes=%d", outcome, err, fake.deletes)
	}
	current, err := readLeaseClaim(claim.LeaseID)
	if err != nil || !reflect.DeepEqual(current, claim) {
		t.Fatalf("claim=%#v err=%v", current, err)
	}
}

func TestSSHRunOperationFenceBlocksRelease(t *testing.T) {
	b, fake := testSSHBackend(t)
	claim := createSSHTestClaim(t, b, fake)
	lease := sshLeaseFromClaim(claim)
	stop, err := b.BeginSSHRunActivity(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.ReleaseLease(ctx, core.ReleaseLeaseRequest{Lease: lease}); err == nil {
		t.Fatal("release passed active run fence")
	}
	if fake.deletes != 0 {
		t.Fatalf("deletes=%d", fake.deletes)
	}
}

func TestSSHRunActivityRejectsChangedTransportBeforeKubernetes(t *testing.T) {
	b, fake := testSSHBackend(t)
	claim := createSSHTestClaim(t, b, fake)
	if _, _, err := core.EnsureTestboxKey(claim.LeaseID); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for key, value := range claim.Labels {
		labels[key] = value
	}
	labels[claimLabelSSHUser] = "root"
	labels[claimLabelSSHPort] = "43210"
	labels[claimLabelSSHHostKey] = bootstrapTestPublicKey(t, 1)
	labels[claimLabelSSHSandboxUID] = "sandbox-uid"
	labels[claimLabelSSHPodUID] = "pod-uid"
	labels[claimLabelSSHContainerID] = "containerd://container-a"
	claim, err := updateLeaseClaimLabelsIfUnchanged(claim.LeaseID, claim, labels)
	if err != nil {
		t.Fatal(err)
	}
	lease := sshLeaseFromClaim(claim)
	lease.SSH, err = b.lifecycle.sshTarget(claim)
	if err != nil {
		t.Fatal(err)
	}
	core.SetServerLeaseClaimSnapshot(&lease.Server, claim, true)
	lease.SSH.ControlScope = "stale-runtime"
	b.lifecycle.newClient = func(context.Context, Config, Runtime) (kubernetesClient, error) {
		t.Fatal("changed transport reached Kubernetes admission")
		return nil, errors.New("unexpected Kubernetes client")
	}
	if _, err := b.BeginSSHRunActivity(context.Background(), lease); !errors.Is(err, core.ErrReleaseLeaseOwnershipChanged) {
		t.Fatalf("changed transport err=%v", err)
	}
}

func TestSSHReleaseReportsTerminalDespiteLocalFinalizationFailure(t *testing.T) {
	b, fake := testSSHBackend(t)
	claim := createSSHTestClaim(t, b, fake)
	want := errors.New("local claim removal denied")
	b.lifecycle.removeClaim = func(string, LeaseClaim) error { return want }
	outcome, err := b.ReleaseLeaseWithOutcome(context.Background(), core.ReleaseLeaseRequest{Lease: sshLeaseFromClaim(claim)})
	if !outcome.Terminal || !errors.Is(err, want) || fake.deletes != 1 {
		t.Fatalf("outcome=%#v err=%v deletes=%d", outcome, err, fake.deletes)
	}
}

func TestSSHReleaseDeleteFailureIsNotTerminal(t *testing.T) {
	b, fake := testSSHBackend(t)
	claim := createSSHTestClaim(t, b, fake)
	want := errors.New("Kubernetes deletion denied")
	fake.deleteErrs = []error{want}
	outcome, err := b.ReleaseLeaseWithOutcome(context.Background(), core.ReleaseLeaseRequest{Lease: sshLeaseFromClaim(claim)})
	if outcome.Terminal || !errors.Is(err, want) {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	current, readErr := readLeaseClaim(claim.LeaseID)
	if readErr != nil || !reflect.DeepEqual(current, claim) {
		t.Fatalf("retained claim=%#v err=%v", current, readErr)
	}
}

func TestSSHReleaseMessageDescribesRetention(t *testing.T) {
	b, _ := testSSHBackend(t)
	b.lifecycle.cfg.AgentSandbox.DeleteOnRelease = false
	message := b.ReleaseLeaseMessage(core.LeaseTarget{LeaseID: "asbx_retained", Server: Server{Name: "claim-retained"}})
	if !strings.Contains(message, "retained lease=asbx_retained") || !strings.Contains(message, "deleteOnRelease=false") || strings.Contains(message, "deleted") {
		t.Fatalf("misleading retention message: %s", message)
	}
}

func TestSSHReleaseRejectsReclaimedRepository(t *testing.T) {
	b, fake := testSSHBackend(t)
	claim := createSSHTestClaim(t, b, fake)
	lease := sshLeaseFromClaim(claim)
	core.SetServerLeaseClaimSnapshot(&lease.Server, claim, true)
	_, err := core.ClaimLeaseForRepoProviderScopePondIfUnchanged(claim.LeaseID, claim.Slug, sshProviderName, claim.ProviderScope, claim.Pond, t.TempDir(), time.Hour, true, claim, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ReleaseLease(context.Background(), core.ReleaseLeaseRequest{Lease: lease}); !errors.Is(err, core.ErrReleaseLeaseOwnershipChanged) {
		t.Fatalf("err=%v", err)
	}
	if fake.deletes != 0 {
		t.Fatalf("deletes=%d", fake.deletes)
	}
}

func TestSSHDoctorRequiresPortForwardRBAC(t *testing.T) {
	b, fake := testSSHBackend(t)
	rule := rbacRule{Resource: podResource, Subresource: "portforward", Namespace: b.lifecycle.cfg.AgentSandbox.Namespace, Verbs: []string{"create"}}
	if _, err := b.Doctor(context.Background(), DoctorRequest{}); err == nil || !strings.Contains(err.Error(), "portforward") {
		t.Fatalf("err=%v", err)
	}
	fake.rbac[rule.String()] = true
	if _, err := b.Doctor(context.Background(), DoctorRequest{}); err != nil {
		t.Fatal(err)
	}
}

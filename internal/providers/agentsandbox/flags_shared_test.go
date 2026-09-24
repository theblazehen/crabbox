package agentsandbox

import (
	"flag"
	"reflect"
	"testing"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
)

func TestProvidersShareParsedAgentSandboxFlags(t *testing.T) {
	for _, providers := range [][]core.Provider{
		{Provider{}, SSHProvider{}},
		{SSHProvider{}, Provider{}},
		{SSHProvider{}},
	} {
		t.Run(providers[0].Spec().Name+"/"+providers[len(providers)-1].Spec().Name, func(t *testing.T) {
			t.Setenv("KUBECONFIG", "")
			defaults := core.BaseConfig()
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			values := make([]any, len(providers))
			for i, provider := range providers {
				values[i] = provider.RegisterFlags(fs, defaults)
			}
			args := []string{
				"--agent-sandbox-kubectl", "test-kubectl",
				"--agent-sandbox-context", "test-context",
				"--agent-sandbox-namespace", "test-namespace",
				"--agent-sandbox-warm-pool", "test-pool",
				"--agent-sandbox-container", "test-container",
				"--agent-sandbox-workdir", "/workspace/test",
				"--agent-sandbox-sandbox-ready-timeout", "2m",
				"--agent-sandbox-pod-ready-timeout", "45s",
				"--agent-sandbox-exec-timeout-secs", "123",
				"--agent-sandbox-delete-on-release=false",
				"--agent-sandbox-forget-missing=true",
			}
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			want := defaults.AgentSandbox
			want.Kubectl = "test-kubectl"
			want.Context = "test-context"
			want.Namespace = "test-namespace"
			want.WarmPool = "test-pool"
			want.Container = "test-container"
			want.Workdir = "/workspace/test"
			want.SandboxReadyTimeout = 2 * time.Minute
			want.PodReadyTimeout = 45 * time.Second
			want.ExecTimeoutSecs = 123
			want.DeleteOnRelease = false
			want.ForgetMissing = true
			for i, provider := range providers {
				cfg := core.BaseConfig()
				cfg.Provider = provider.Spec().Name
				if err := provider.ApplyFlags(&cfg, fs, values[i]); err != nil {
					t.Fatalf("provider=%s: %v", provider.Spec().Name, err)
				}
				if !reflect.DeepEqual(cfg.AgentSandbox, want) {
					t.Errorf("provider=%s config=%#v; want %#v", provider.Spec().Name, cfg.AgentSandbox, want)
				}
				if !core.DeleteOnReleaseExplicit(cfg, provider.Spec().Name) {
					t.Errorf("provider=%s delete policy not marked explicit", provider.Spec().Name)
				}
			}
		})
	}
}

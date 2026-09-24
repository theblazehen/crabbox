package agentsandbox

import (
	"flag"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
)

// registerFlags binds the shared agent-sandbox configuration namespace. Both
// transports own that namespace, and core registers every provider on one
// FlagSet, so the first call wires the bindings and later calls reuse the same
// parsed storage. Values stay reachable through the FlagSet because the shared
// engine's typed storage is only handed to the registrant.
func registerFlags(fs *flag.FlagSet, defaults core.Config) any {
	if fs.Lookup("agent-sandbox-kubectl") == nil {
		core.RegisterAgentSandboxConfigFlags(fs, defaults.AgentSandbox)
	}
	return fs
}

func applyFlags(cfg *core.Config, fs *flag.FlagSet, values any) error {
	registered, ok := values.(*flag.FlagSet)
	if !ok {
		return nil
	}
	value := func(name string) any {
		return registered.Lookup(name).Value.(flag.Getter).Get()
	}
	accepted := false
	apply := func(name string, assign func()) {
		if !core.FlagWasSet(fs, name) {
			return
		}
		assign()
		accepted = true
	}
	apply("agent-sandbox-kubectl", func() { cfg.AgentSandbox.Kubectl = value("agent-sandbox-kubectl").(string) })
	apply("agent-sandbox-kubeconfig", func() {
		cfg.AgentSandbox.Kubeconfig = core.ExpandUserPath(value("agent-sandbox-kubeconfig").(string))
	})
	apply("agent-sandbox-context", func() { cfg.AgentSandbox.Context = value("agent-sandbox-context").(string) })
	apply("agent-sandbox-namespace", func() { cfg.AgentSandbox.Namespace = value("agent-sandbox-namespace").(string) })
	apply("agent-sandbox-warm-pool", func() { cfg.AgentSandbox.WarmPool = value("agent-sandbox-warm-pool").(string) })
	apply("agent-sandbox-container", func() { cfg.AgentSandbox.Container = value("agent-sandbox-container").(string) })
	apply("agent-sandbox-workdir", func() { cfg.AgentSandbox.Workdir = value("agent-sandbox-workdir").(string) })
	apply("agent-sandbox-sandbox-ready-timeout", func() {
		cfg.AgentSandbox.SandboxReadyTimeout = value("agent-sandbox-sandbox-ready-timeout").(time.Duration)
	})
	apply("agent-sandbox-pod-ready-timeout", func() {
		cfg.AgentSandbox.PodReadyTimeout = value("agent-sandbox-pod-ready-timeout").(time.Duration)
	})
	apply("agent-sandbox-exec-timeout-secs", func() { cfg.AgentSandbox.ExecTimeoutSecs = value("agent-sandbox-exec-timeout-secs").(int) })
	apply("agent-sandbox-forget-missing", func() { cfg.AgentSandbox.ForgetMissing = value("agent-sandbox-forget-missing").(bool) })
	deleteOnRelease := false
	apply("agent-sandbox-delete-on-release", func() {
		cfg.AgentSandbox.DeleteOnRelease = value("agent-sandbox-delete-on-release").(bool)
		deleteOnRelease = true
	})
	core.RecordProviderFlagInputs(cfg, accepted, providerName)
	if deleteOnRelease {
		provider := providerName
		if cfg.Provider == sshProviderName {
			provider = sshProviderName
		}
		core.MarkDeleteOnReleaseExplicit(cfg, provider)
	}
	return validateConfig(*cfg)
}

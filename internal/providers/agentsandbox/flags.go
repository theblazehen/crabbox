package agentsandbox

import (
	"flag"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
)

func registerFlags(fs *flag.FlagSet, defaults core.Config) any {
	// Both transports own the same configuration namespace. Core registers all
	// providers on one FlagSet; the hidden SSH proxy registers only its provider.
	if fs.Lookup("agent-sandbox-kubectl") == nil {
		fs.String("agent-sandbox-kubectl", defaults.AgentSandbox.Kubectl, "kubectl binary or path")
		fs.String("agent-sandbox-kubeconfig", defaults.AgentSandbox.Kubeconfig, "Kubernetes kubeconfig path")
		fs.String("agent-sandbox-context", defaults.AgentSandbox.Context, "Kubernetes context")
		fs.String("agent-sandbox-namespace", defaults.AgentSandbox.Namespace, "Kubernetes namespace")
		fs.String("agent-sandbox-warm-pool", defaults.AgentSandbox.WarmPool, "Agent Sandbox SandboxWarmPool name")
		fs.String("agent-sandbox-container", defaults.AgentSandbox.Container, "container name for exec/tar operations (empty = default container)")
		fs.String("agent-sandbox-workdir", defaults.AgentSandbox.Workdir, "absolute working directory inside the sandbox")
		fs.Duration("agent-sandbox-sandbox-ready-timeout", defaults.AgentSandbox.SandboxReadyTimeout, "SandboxClaim/Sandbox readiness timeout")
		fs.Duration("agent-sandbox-pod-ready-timeout", defaults.AgentSandbox.PodReadyTimeout, "sandbox pod readiness timeout")
		fs.Int("agent-sandbox-exec-timeout-secs", defaults.AgentSandbox.ExecTimeoutSecs, "command timeout in seconds (0 = no provider deadline)")
		fs.Bool("agent-sandbox-delete-on-release", defaults.AgentSandbox.DeleteOnRelease, "delete the SandboxClaim on release")
		fs.Bool("agent-sandbox-forget-missing", defaults.AgentSandbox.ForgetMissing, "remove the local claim when stop sees a missing Kubernetes claim")
	}
	return fs
}

func applyFlags(cfg *core.Config, fs *flag.FlagSet, values any) error {
	registered, ok := values.(*flag.FlagSet)
	if !ok {
		return nil
	}
	if core.FlagWasSet(fs, "agent-sandbox-kubectl") {
		cfg.AgentSandbox.Kubectl = registered.Lookup("agent-sandbox-kubectl").Value.(flag.Getter).Get().(string)
	}
	if core.FlagWasSet(fs, "agent-sandbox-kubeconfig") {
		cfg.AgentSandbox.Kubeconfig = expandUserPath(registered.Lookup("agent-sandbox-kubeconfig").Value.(flag.Getter).Get().(string))
	}
	if core.FlagWasSet(fs, "agent-sandbox-context") {
		cfg.AgentSandbox.Context = registered.Lookup("agent-sandbox-context").Value.(flag.Getter).Get().(string)
	}
	if core.FlagWasSet(fs, "agent-sandbox-namespace") {
		cfg.AgentSandbox.Namespace = registered.Lookup("agent-sandbox-namespace").Value.(flag.Getter).Get().(string)
	}
	if core.FlagWasSet(fs, "agent-sandbox-warm-pool") {
		cfg.AgentSandbox.WarmPool = registered.Lookup("agent-sandbox-warm-pool").Value.(flag.Getter).Get().(string)
	}
	if core.FlagWasSet(fs, "agent-sandbox-container") {
		cfg.AgentSandbox.Container = registered.Lookup("agent-sandbox-container").Value.(flag.Getter).Get().(string)
	}
	if core.FlagWasSet(fs, "agent-sandbox-workdir") {
		cfg.AgentSandbox.Workdir = registered.Lookup("agent-sandbox-workdir").Value.(flag.Getter).Get().(string)
	}
	if core.FlagWasSet(fs, "agent-sandbox-sandbox-ready-timeout") {
		cfg.AgentSandbox.SandboxReadyTimeout = registered.Lookup("agent-sandbox-sandbox-ready-timeout").Value.(flag.Getter).Get().(time.Duration)
	}
	if core.FlagWasSet(fs, "agent-sandbox-pod-ready-timeout") {
		cfg.AgentSandbox.PodReadyTimeout = registered.Lookup("agent-sandbox-pod-ready-timeout").Value.(flag.Getter).Get().(time.Duration)
	}
	if core.FlagWasSet(fs, "agent-sandbox-exec-timeout-secs") {
		cfg.AgentSandbox.ExecTimeoutSecs = registered.Lookup("agent-sandbox-exec-timeout-secs").Value.(flag.Getter).Get().(int)
	}
	if core.FlagWasSet(fs, "agent-sandbox-delete-on-release") {
		cfg.AgentSandbox.DeleteOnRelease = registered.Lookup("agent-sandbox-delete-on-release").Value.(flag.Getter).Get().(bool)
		provider := providerName
		if cfg.Provider == sshProviderName {
			provider = sshProviderName
		}
		core.MarkDeleteOnReleaseExplicit(cfg, provider)
	}
	if core.FlagWasSet(fs, "agent-sandbox-forget-missing") {
		cfg.AgentSandbox.ForgetMissing = registered.Lookup("agent-sandbox-forget-missing").Value.(flag.Getter).Get().(bool)
	}
	return validateConfig(*cfg)
}

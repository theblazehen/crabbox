package cli

import (
	"context"
	"flag"
	"io"
	"strings"
)

func (a App) providerSSHProxy(ctx context.Context, args []string) error {
	if len(args) < 2 || strings.TrimSpace(args[0]) == "" || strings.TrimSpace(args[1]) == "" || strings.HasPrefix(args[1], "-") {
		return exit(2, "provider SSH proxy requires PROVIDER LEASE [provider flags]")
	}
	provider, err := ProviderFor(args[0])
	if err != nil {
		return err
	}
	cfg, err := loadConfigWithOverrides("", provider.Name())
	if err != nil {
		return err
	}
	stderr := a.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	fs := flag.NewFlagSet("__provider-ssh-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := provider.RegisterFlags(fs, cfg)
	if err := fs.Parse(args[2:]); err != nil {
		return exit(2, "%v", err)
	}
	if fs.NArg() != 0 {
		return exit(2, "provider SSH proxy accepts only provider flags after LEASE; unexpected argument %q", fs.Arg(0))
	}
	if err := provider.ApplyFlags(&cfg, fs, values); err != nil {
		return err
	}
	// This is an already selected transport, not a new allocation. Never route
	// it through a configured broker or through another provider's defaults.
	setProviderSelection(&cfg, provider.Name(), providerSelectionFlag)
	cfg.brokerProvider = ""
	// Reserve stdout exclusively for the SSH byte stream, including during
	// provider configuration and any local commands the provider starts.
	rt := runtimeForApp(App{Stdout: stderr, Stderr: stderr})
	rt.Exec = commandRunnerWithChildCredentialBoundary(rt.Exec, externalDesktopChildEnvDenylist(cfg, cfg.TargetOS))
	backend, err := configureProviderBackend(provider, &cfg, rt)
	if err != nil {
		return err
	}
	proxy, ok := backend.(SSHProxyBackend)
	if !ok {
		return exit(2, "provider %q does not support an SSH stdio proxy", provider.Name())
	}
	stdout := a.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	return proxy.ProxySSH(ctx, args[1], a.input(), stdout, stderr)
}

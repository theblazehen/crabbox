package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

type providerSSHProxyTestProvider struct {
	configure func(Config, Runtime) (Backend, error)
}

func (*providerSSHProxyTestProvider) Name() string { return "ssh-proxy-test" }
func (*providerSSHProxyTestProvider) Aliases() []string {
	return []string{"ssh-proxy-test-alias"}
}
func (p *providerSSHProxyTestProvider) Spec() ProviderSpec {
	return ProviderSpec{
		Name: p.Name(), Kind: ProviderKindSSHLease,
		Targets:  []TargetSpec{{OS: targetLinux}},
		Features: FeatureSet{FeatureSSH}, Coordinator: CoordinatorSupported,
	}
}
func (*providerSSHProxyTestProvider) RegisterFlags(fs *flag.FlagSet, cfg Config) any {
	return fs.String("proxy-route", cfg.Blacksmith.Org, "test proxy route")
}
func (*providerSSHProxyTestProvider) ApplyFlags(cfg *Config, _ *flag.FlagSet, values any) error {
	cfg.Blacksmith.Org = *values.(*string)
	return nil
}
func (p *providerSSHProxyTestProvider) Configure(cfg Config, rt Runtime) (Backend, error) {
	return p.configure(cfg, rt)
}

type providerSSHProxyTestBackend struct {
	// A nil embedded lease backend makes accidental Resolve/Acquire/Touch calls
	// fail, and would qualify for coordinator wrapping if loadBackend were used.
	SSHLeaseBackend
	spec  ProviderSpec
	proxy func(context.Context, string, io.Reader, io.Writer, io.Writer) error
}

func (b *providerSSHProxyTestBackend) Spec() ProviderSpec { return b.spec }
func (b *providerSSHProxyTestBackend) ProxySSH(ctx context.Context, lease string, in io.Reader, out, stderr io.Writer) error {
	return b.proxy(ctx, lease, in, out, stderr)
}

type providerSSHProxyUnsupportedBackend struct{ spec ProviderSpec }

func (b providerSSHProxyUnsupportedBackend) Spec() ProviderSpec { return b.spec }

func setupProviderSSHProxyTest(t *testing.T) *providerSSHProxyTestProvider {
	t.Helper()
	clearConfigEnv(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("CRABBOX_CONFIG", filepath.Join(root, "config.yaml"))
	writeFile(t, filepath.Join(root, "config.yaml"), "provider: hetzner\nblacksmith:\n  org: config-route\n")
	p := &providerSSHProxyTestProvider{}
	RegisterProvider(p)
	t.Cleanup(func() {
		delete(providerRegistry, p.Name())
		for _, alias := range p.Aliases() {
			delete(providerRegistry, alias)
		}
	})
	return p
}

func TestProviderSSHProxyDispatchesRawStreamsDirectly(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprintf("flag_override=%v", override), func(t *testing.T) {
			p := setupProviderSSHProxyTest(t)
			t.Setenv("CRABBOX_PROVIDER", "hetzner")
			t.Setenv("CRABBOX_COORDINATOR", "https://coordinator.example.test")
			payload := []byte{0, 255, '\n', 'S', 'S', 'H', '\r', 0}
			var stdout, stderr bytes.Buffer
			called := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p.configure = func(cfg Config, rt Runtime) (Backend, error) {
				wantRoute := "config-route"
				if override {
					wantRoute = "explicit route"
				}
				if cfg.Provider != p.Name() || cfg.Blacksmith.Org != wantRoute {
					t.Fatalf("configuration provider=%q route=%q", cfg.Provider, cfg.Blacksmith.Org)
				}
				if rt.Clock == nil || rt.Exec == nil || rt.Stdout == nil || rt.Stderr == nil {
					t.Fatal("provider runtime is not initialized")
				}
				fmt.Fprintln(rt.Stdout, "configuration diagnostic")
				return &providerSSHProxyTestBackend{spec: p.Spec(), proxy: func(gotCtx context.Context, lease string, in io.Reader, out, errOut io.Writer) error {
					called = true
					if gotCtx != ctx || lease != "lease-123" || out != &stdout || errOut != &stderr {
						t.Fatal("proxy context, lease, or streams were not forwarded")
					}
					fmt.Fprintln(errOut, "transport diagnostic")
					_, err := io.Copy(out, in)
					return err
				}}, nil
			}
			args := []string{"__provider-ssh-proxy", p.Aliases()[0], "lease-123"}
			if override {
				args = append(args, "--proxy-route", "explicit route")
			}
			app := App{Stdin: bytes.NewReader(payload), Stdout: &stdout, Stderr: &stderr}
			if err := app.Run(ctx, args); err != nil {
				t.Fatal(err)
			}
			if !called || !bytes.Equal(stdout.Bytes(), payload) {
				t.Fatalf("called=%v stdout=%q; want exact binary payload %q", called, stdout.Bytes(), payload)
			}
			if got := stderr.String(); got != "configuration diagnostic\ntransport diagnostic\n" {
				t.Fatalf("stderr=%q", got)
			}
		})
	}
}

func TestProviderSSHProxyRejectsMalformedInvocationBeforeConfigure(t *testing.T) {
	p := setupProviderSSHProxyTest(t)
	p.configure = func(Config, Runtime) (Backend, error) {
		t.Fatal("malformed invocation configured a provider")
		return nil, nil
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "requires PROVIDER LEASE"},
		{[]string{p.Name()}, "requires PROVIDER LEASE"},
		{[]string{p.Name(), " "}, "requires PROVIDER LEASE"},
		{[]string{p.Name(), "--proxy-route"}, "requires PROVIDER LEASE"},
		{[]string{"missing-proxy-provider", "lease"}, "unknown provider"},
		{[]string{p.Name(), "lease", "extra"}, "unexpected argument"},
		{[]string{p.Name(), "lease", "--unknown-flag"}, "flag provided but not defined"},
	} {
		var stdout, stderr bytes.Buffer
		err := (App{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), append([]string{"__provider-ssh-proxy"}, tc.args...))
		var exitErr ExitError
		if err == nil || !strings.Contains(err.Error(), tc.want) || !AsExitError(err, &exitErr) || exitErr.Code != 2 {
			t.Errorf("args=%q error=%v; want exit 2 containing %q", tc.args, err, tc.want)
		}
		if stdout.Len() != 0 {
			t.Errorf("args=%q polluted stdout: %q", tc.args, stdout.String())
		}
	}
}

func TestProviderSSHProxyReturnsBackendFailures(t *testing.T) {
	for _, mode := range []string{"unsupported", "configure", "transport"} {
		t.Run(mode, func(t *testing.T) {
			p := setupProviderSSHProxyTest(t)
			failure := errors.New("test proxy failure")
			p.configure = func(Config, Runtime) (Backend, error) {
				switch mode {
				case "unsupported":
					return providerSSHProxyUnsupportedBackend{spec: p.Spec()}, nil
				case "configure":
					return nil, failure
				default:
					return &providerSSHProxyTestBackend{spec: p.Spec(), proxy: func(context.Context, string, io.Reader, io.Writer, io.Writer) error {
						return failure
					}}, nil
				}
			}
			var stdout bytes.Buffer
			err := (App{Stdout: &stdout, Stderr: io.Discard}).Run(context.Background(), []string{"__provider-ssh-proxy", p.Name(), "lease"})
			if mode == "unsupported" {
				var exitErr ExitError
				if err == nil || !strings.Contains(err.Error(), "does not support an SSH stdio proxy") || !AsExitError(err, &exitErr) || exitErr.Code != 2 {
					t.Fatalf("unsupported backend error=%v", err)
				}
			} else if !errors.Is(err, failure) {
				t.Fatalf("error=%v; want %v", err, failure)
			}
			if stdout.Len() != 0 {
				t.Fatalf("failure polluted stdout: %q", stdout.String())
			}
		})
	}
}

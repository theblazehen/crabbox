package agentsandbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
	xssh "golang.org/x/crypto/ssh"
)

func TestSSHTargetPinsHostKeyAndQuotesLiteralProxyArguments(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := core.BaseConfig()
	cfg.Provider = sshProviderName
	cfg.AgentSandbox.Kubeconfig = filepath.Join(t.TempDir(), "config %h 'literal'")
	cfg.AgentSandbox.Context = "personal"
	cfg.AgentSandbox.Workdir = "/workspace/$(touch unexpected)"
	leaseID := newLeaseID()
	keyPath, err := core.TestboxKeyPath(leaseID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("stored private key"), 0600); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := xssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	hostKey := strings.TrimSpace(string(xssh.MarshalAuthorizedKey(sshPublic)))
	claim := LeaseClaim{LeaseID: leaseID, Provider: sshProviderName, ProviderScope: claimScope(cfg), Labels: map[string]string{
		claimLabelSSHUser: "root", claimLabelSSHHostKey: hostKey, claimLabelSSHPort: "43210",
	}}
	b := &backend{cfg: cfg}
	target, err := b.sshTarget(claim)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args, _ := b.sshProxyArgs(executable, leaseID)
	for i := range args {
		args[i] = core.ShellQuote(strings.ReplaceAll(args[i], "%", "%%"))
	}
	if target.ProxyCommand != strings.Join(args, " ") || target.SSHHostKey != hostKey || target.Key != keyPath || target.User != "root" || target.Port != "43210" || !target.NoControlMaster || !target.SSHConfigProxy {
		t.Fatalf("target=%#v", target)
	}
	if target.HostKeyAlias != leaseID || target.KnownHostsFile != filepath.Join(filepath.Dir(keyPath), "known_hosts") {
		t.Fatalf("target has no isolated authoritative trust: %#v", target)
	}
	if _, err := os.Stat(target.KnownHostsFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only target construction mutated trust file: %v", err)
	}
	for _, port := range []string{"1024", "65535"} {
		claim.Labels[claimLabelSSHPort] = port
		if target, err := b.sshTarget(claim); err != nil || target.Port != port {
			t.Fatalf("port %q: target=%#v error=%v", port, target, err)
		}
	}
	for _, port := range []string{"", "0", "1023", "65536", "-43210", "+43210", "043210", "43210 ", " 43210", "43210\n", "four", "999999999999999999999999"} {
		claim.Labels[claimLabelSSHPort] = port
		if _, err := b.sshTarget(claim); err == nil || !strings.Contains(err.Error(), "pinned SSH port") {
			t.Fatalf("port %q: error=%v", port, err)
		}
	}
	claim.Labels[claimLabelSSHPort] = "43210"
	claim.Labels[claimLabelSSHHostKey] = "not a host key"
	if _, err := b.sshTarget(claim); err == nil {
		t.Fatal("target accepted malformed host key")
	}
}

func TestParseSSHForwardPortOnlyAcceptsLoopbackSSHMapping(t *testing.T) {
	for _, tt := range []struct{ line, want string }{
		{"Forwarding from 127.0.0.1:38177 -> 43210", "38177"},
		{"Forwarding from 127.0.0.1:65535 -> 43210\r", "65535"},
		{"Forwarding from 0.0.0.0:38177 -> 43210", ""},
		{"Forwarding from [::1]:38177 -> 43210", ""},
		{"Forwarding from 127.0.0.1:38177 -> 22", ""},
		{"Forwarding from 127.0.0.1:38177 -> 2222", ""},
		{"Forwarding from 127.0.0.1:65536 -> 43210", ""},
		{"Forwarding from 127.0.0.1:0 -> 43210", ""},
		{"Forwarding from 127.0.0.1:+22 -> 43210", ""},
		{"Forwarding from 127.0.0.1:22 -> 43210 extra", ""},
		{"error: Forwarding from 127.0.0.1:38177 -> 43210", ""},
	} {
		t.Run(tt.line, func(t *testing.T) {
			got, ok := parseSSHForwardPort(tt.line, "43210")
			if got != tt.want || ok != (tt.want != "") {
				t.Fatalf("parseSSHForwardPort(%q) = %q, %t; want %q", tt.line, got, ok, tt.want)
			}
		})
	}
}

func TestSSHForwardOutputBoundsLinesAndHandlesFragments(t *testing.T) {
	ports := make(chan string, 1)
	parser := &sshForwardOutput{ports: ports, remotePort: "43210"}
	_, _ = parser.Write([]byte(strings.Repeat("x", sshProxyOutputLineLimit+1)))
	_, _ = parser.Write([]byte("Forwarding from 127.0.0.1:9999 -> 43210\n"))
	select {
	case port := <-ports:
		t.Fatalf("accepted suffix of oversized line: %s", port)
	default:
	}
	_, _ = parser.Write([]byte("Forwarding from 127.0.0.1:"))
	_, _ = parser.Write([]byte("12345 -> 43210\nHandling connection for 12345\n"))
	select {
	case port := <-ports:
		if port != "12345" {
			t.Fatalf("port = %s", port)
		}
	default:
		t.Fatal("fragmented readiness was not recognized")
	}
}

func TestSSHProxyArgsPinRoutingWithoutChangingImplicitContainerScope(t *testing.T) {
	cfg := core.BaseConfig()
	cfg.AgentSandbox.Kubeconfig = filepath.Join(t.TempDir(), "config with spaces")
	cfg.AgentSandbox.Kubectl = "/tools/kubectl"
	cfg.AgentSandbox.Context = "context 'quoted'"
	cfg.AgentSandbox.Namespace = "sandboxes"
	cfg.AgentSandbox.WarmPool = "pool"
	cfg.AgentSandbox.Container = ""
	cfg.AgentSandbox.Workdir = "/workspace/repo"
	b := &backend{cfg: cfg}
	args, childEnv := b.sshProxyArgs("/tools/crabbox", "asbx_test")
	want := []string{
		"/tools/crabbox", "__provider-ssh-proxy", sshProviderName, "asbx_test",
		"--agent-sandbox-kubectl=/tools/kubectl",
		"--agent-sandbox-kubeconfig=" + cfg.AgentSandbox.Kubeconfig,
		"--agent-sandbox-context=context 'quoted'",
		"--agent-sandbox-namespace=sandboxes",
		"--agent-sandbox-warm-pool=pool",
		"--agent-sandbox-container=",
		"--agent-sandbox-workdir=/workspace/repo",
	}
	if !reflect.DeepEqual(args, want) || len(childEnv) != 0 {
		t.Fatalf("args=%q env=%v, want %q", args, childEnv, want)
	}
	cfg.AgentSandbox.Kubeconfig = ""
	configs := filepath.Join(t.TempDir(), "one") + string(filepath.ListSeparator) + filepath.Join(t.TempDir(), "two")
	t.Setenv("KUBECONFIG", configs)
	b.cfg = cfg
	args, childEnv = b.sshProxyArgs("/tools/crabbox", "asbx_test")
	if childEnv["KUBECONFIG"] != configs || args[5] != "--agent-sandbox-kubeconfig=" {
		t.Fatalf("multi-file kubeconfig binding: args=%q env=%v", args, childEnv)
	}
}

type sshTransportRunnerFunc func(context.Context, LocalCommandRequest) (LocalCommandResult, error)

func (f sshTransportRunnerFunc) Run(ctx context.Context, req LocalCommandRequest) (LocalCommandResult, error) {
	return f(ctx, req)
}

func TestSSHForwardRemoteEOFCancelsAndReapsWithoutWaitingForStdin(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, err = io.WriteString(conn, "SSH-2.0-test\r\n")
			_ = conn.Close()
		}
		serverDone <- err
	}()
	input, inputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	var output, stderr bytes.Buffer
	reaped := make(chan struct{})
	cfg := core.BaseConfig()
	cfg.AgentSandbox.Kubectl = "kubectl-test"
	cfg.AgentSandbox.Context = "personal"
	cfg.AgentSandbox.Namespace = "sandboxes"
	cfg.AgentSandbox.Kubeconfig = "/config/path"
	var gotRequest LocalCommandRequest
	b := &backend{cfg: cfg, rt: Runtime{Exec: sshTransportRunnerFunc(func(ctx context.Context, req LocalCommandRequest) (LocalCommandResult, error) {
		gotRequest = req
		fmt.Fprintf(req.Stdout, "Forwarding from 127.0.0.1:%s -> 43210\n", port)
		fmt.Fprintln(req.Stderr, "diagnostic")
		<-ctx.Done()
		close(reaped)
		return LocalCommandResult{ExitCode: 1}, ctx.Err()
	})}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	checks := 0
	if err := b.forwardSSH(ctx, "sandbox-pod", "43210", input, &output, &stderr, func() error { checks++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-reaped:
	default:
		t.Fatal("proxy returned before command runner was reaped")
	}
	if output.String() != "SSH-2.0-test\r\n" || stderr.String() != "diagnostic\n" || checks != 1 {
		t.Fatalf("output=%q stderr=%q checks=%d", output.String(), stderr.String(), checks)
	}
	want := []string{"--kubeconfig=/config/path", "--context=personal", "--namespace=sandboxes", "port-forward", "--address=127.0.0.1", "pod/sandbox-pod", ":43210"}
	if gotRequest.Name != "kubectl-test" || !reflect.DeepEqual(gotRequest.Args, want) || !gotRequest.DisableOutputCapture {
		t.Fatalf("kubectl request = %#v", gotRequest)
	}
}

func TestSSHForwardRejectsPostStartIdentityChangeAndReaps(t *testing.T) {
	reaped := make(chan struct{})
	b := &backend{cfg: core.BaseConfig(), rt: Runtime{Exec: sshTransportRunnerFunc(func(ctx context.Context, req LocalCommandRequest) (LocalCommandResult, error) {
		fmt.Fprintln(req.Stdout, "Forwarding from 127.0.0.1:12345 -> 43210")
		<-ctx.Done()
		close(reaped)
		return LocalCommandResult{}, ctx.Err()
	})}}
	changed := errors.New("pod UID changed")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := b.forwardSSH(ctx, "pod", "43210", strings.NewReader(""), io.Discard, io.Discard, func() error { return changed })
	if !errors.Is(err, changed) {
		t.Fatalf("error=%v, want identity failure", err)
	}
	select {
	case <-reaped:
	default:
		t.Fatal("identity failure leaked command runner")
	}
}

func TestSSHForwardClientEOFCancelsAndReapsWhileServerRemainsOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	serverDone := make(chan error, 1)
	closeServer := make(chan struct{})
	defer close(closeServer)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			// Keep the server side open until the proxy closes its connection.
			// A half-close-and-wait implementation deadlocks against this peer.
			_, err = io.Copy(io.Discard, conn)
		}
		serverDone <- err
		<-closeServer
	}()
	reaped := make(chan struct{})
	b := &backend{cfg: core.BaseConfig(), rt: Runtime{Exec: sshTransportRunnerFunc(func(ctx context.Context, req LocalCommandRequest) (LocalCommandResult, error) {
		fmt.Fprintf(req.Stdout, "Forwarding from 127.0.0.1:%s -> 43210\n", port)
		<-ctx.Done()
		close(reaped)
		return LocalCommandResult{}, ctx.Err()
	})}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := b.forwardSSH(ctx, "pod", "43210", strings.NewReader(""), io.Discard, io.Discard, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reaped:
	default:
		t.Fatal("client EOF returned without reaping kubectl")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("client EOF did not close the server connection")
	}
}

func TestSSHProxyProcessExitInterruptsBlockedStreams(t *testing.T) {
	conn, remote := net.Pipe()
	defer conn.Close()
	defer remote.Close()
	input, inputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	done := make(chan error, 1)
	done <- errors.New("forwarding failed")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	exited, err := copySSHProxyStreams(ctx, conn, input, io.Discard, done)
	if !exited || err == nil || !strings.Contains(err.Error(), "forwarding failed") {
		t.Fatalf("exited=%t error=%v", exited, err)
	}
}

func TestSSHProxyRejectsMissingOrInvalidPortBeforeClientCreation(t *testing.T) {
	for _, port := range []string{"", "22", "1023", "65536", "-43210", "+43210", "043210", "43210 ", " 43210", "43210\n", "invalid"} {
		t.Run(fmt.Sprintf("port=%q", port), func(t *testing.T) {
			b, fake := testSSHBackend(t)
			claim := createSSHTestClaim(t, b, fake)
			if port != "" {
				labels := cloneStringMap(claim.Labels)
				labels[claimLabelSSHPort] = port
				var err error
				claim, err = updateLeaseClaimLabelsIfUnchanged(claim.LeaseID, claim, labels)
				if err != nil {
					t.Fatal(err)
				}
			}
			b.lifecycle.newClient = func(context.Context, Config, Runtime) (kubernetesClient, error) {
				t.Fatal("invalid port created a Kubernetes client")
				return nil, errors.New("unexpected client creation")
			}
			b.lifecycle.rt.Exec = sshTransportRunnerFunc(func(context.Context, LocalCommandRequest) (LocalCommandResult, error) {
				t.Fatal("invalid port started port forwarding")
				return LocalCommandResult{}, errors.New("unexpected port forwarding")
			})
			if err := b.ProxySSH(context.Background(), claim.LeaseID, strings.NewReader(""), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "pinned SSH port") {
				t.Fatalf("error=%v", err)
			}
			stored, err := readLeaseClaim(claim.LeaseID)
			if err != nil || !reflect.DeepEqual(stored, claim) {
				t.Fatalf("proxy mutated claim: stored=%#v error=%v", stored, err)
			}
		})
	}
}

func TestSSHReadOnlyHealthRequiresPinnedAuthenticatedEndpoint(t *testing.T) {
	for _, scenario := range []string{"healthy", "wrong host key", "rejected client key", "daemon absent", "container restarted"} {
		t.Run(scenario, func(t *testing.T) {
			lifecycle, client, ready, claim := newSSHBootstrapTestSetup(t)
			b := &sshLeaseBackend{lifecycle: lifecycle}
			_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			hostSigner, err := xssh.NewSignerFromKey(hostPrivate)
			if err != nil {
				t.Fatal(err)
			}
			client.output = bootstrapTestOutput(strings.TrimSpace(string(xssh.MarshalAuthorizedKey(hostSigner.PublicKey()))), "43210")
			claim, err = lifecycle.prepareSSH(t.Context(), client, ready, claim)
			if err != nil {
				t.Fatal(err)
			}
			target, err := lifecycle.sshTarget(claim)
			if err != nil {
				t.Fatal(err)
			}
			priorTrust, err := os.ReadFile(target.KnownHostsFile)
			if err != nil {
				t.Fatal(err)
			}
			_, publicKey, err := core.EnsureTestboxKey(claim.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			authorized, _, _, _, err := xssh.ParseAuthorizedKey([]byte(publicKey))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "wrong host key" {
				_, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				hostSigner, err = xssh.NewSignerFromKey(private)
				if err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "container restarted" {
				client.pods[lifecycle.cfg.AgentSandbox.Namespace+"/claim="+ready.ClaimName][0].ContainerIDs[ready.Container] = "containerd://restarted"
			}
			serverConfig := &xssh.ServerConfig{PublicKeyCallback: func(meta xssh.ConnMetadata, key xssh.PublicKey) (*xssh.Permissions, error) {
				if scenario == "rejected client key" || meta.User() != "root" || !bytes.Equal(key.Marshal(), authorized.Marshal()) {
					return nil, errors.New("unauthorized client")
				}
				return nil, nil
			}}
			serverConfig.AddHostKey(hostSigner)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			if scenario == "daemon absent" {
				listener.Close()
			}
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				for {
					tcp, err := listener.Accept()
					if err != nil {
						return
					}
					conn, channels, requests, err := xssh.NewServerConn(tcp, serverConfig)
					if err == nil {
						go xssh.DiscardRequests(requests)
						for channel := range channels {
							t.Error("read-only health attempted to open an SSH channel")
							channel.Reject(xssh.Prohibited, "read-only health")
						}
						conn.Close()
					}
					tcp.Close()
				}
			}()
			defer func() { listener.Close(); <-serverDone }()
			lifecycle.rt.Exec = sshTransportRunnerFunc(func(ctx context.Context, req LocalCommandRequest) (LocalCommandResult, error) {
				fmt.Fprintf(req.Stdout, "Forwarding from 127.0.0.1:%s -> 43210\n", port)
				<-ctx.Done()
				return LocalCommandResult{}, ctx.Err()
			})
			bootstrapExecs := len(client.execs)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			view, err := b.Status(ctx, StatusRequest{ID: claim.LeaseID})
			if err != nil {
				t.Fatal(err)
			}
			wantReady := scenario == "healthy"
			if view.Ready != wantReady || view.Labels["pod_ready"] != "true" || view.Labels["ssh_ready"] != fmt.Sprint(wantReady) {
				t.Fatalf("incorrect readiness: %#v", view)
			}
			lease, err := b.Resolve(ctx, core.ResolveRequest{ID: claim.LeaseID, StatusOnly: true, NoLocalStateMutations: true})
			if err != nil || (lease.Server.Status == statusViewReady) != wantReady {
				t.Fatalf("inspect readiness=%#v, err=%v", lease.Server, err)
			}
			views, err := b.List(ctx, ListRequest{})
			if err != nil || len(views) != 1 || (views[0].Status == statusViewReady) != wantReady {
				t.Fatalf("list readiness=%#v, err=%v", views, err)
			}
			stored, err := readLeaseClaim(claim.LeaseID)
			if err != nil || !reflect.DeepEqual(stored, claim) {
				t.Fatalf("read-only health changed claim: %#v, %v", stored, err)
			}
			trust, err := os.ReadFile(target.KnownHostsFile)
			if err != nil || !bytes.Equal(trust, priorTrust) || len(client.execs) != bootstrapExecs {
				t.Fatalf("read-only health bootstrapped or repinned: %v", err)
			}
			if scenario == "healthy" {
				reuseCtx, reuseCancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer reuseCancel()
				lease, reused := b.reusePreparedSSH(reuseCtx, client, ready, claim)
				if !reused {
					t.Fatal("healthy prepared endpoint was not reused")
				}
				if len(client.execs) != bootstrapExecs {
					t.Fatalf("healthy reuse re-ran bootstrap: execs=%d want=%d", len(client.execs), bootstrapExecs)
				}
				if lease.SSH.ControlScope == "" || lease.SSH.NoControlMaster {
					t.Fatalf("healthy reuse disabled persistent transport: %#v", lease.SSH)
				}
			}
		})
	}
}

func TestSSHProxyRejectsIdentityChangesBeforeAndAfterForwarding(t *testing.T) {
	for _, scenario := range []string{"before claim", "after claim", "before container", "after container"} {
		t.Run(scenario, func(t *testing.T) {
			parts := strings.Split(scenario, " ")
			phase, identity := parts[0], parts[1]
			lifecycle, client, ready, claim := newSSHBootstrapTestSetup(t)
			b := &sshLeaseBackend{lifecycle: lifecycle}
			fake := client.fakeKubernetesClient
			claim, err := lifecycle.prepareSSH(t.Context(), client, ready, claim)
			if err != nil {
				t.Fatal(err)
			}
			live := fake.objects[sandboxClaimResource+"/"+b.lifecycle.cfg.AgentSandbox.Namespace+"/"+claimNameFromLocalClaim(claim)]
			mutate := func() {
				if identity == "claim" {
					live.Metadata.UID = "replacement-claim-uid"
				} else {
					fake.pods[lifecycle.cfg.AgentSandbox.Namespace+"/claim="+ready.ClaimName][0].ContainerIDs[ready.Container] = "containerd://replacement"
				}
			}
			if phase == "before" {
				mutate()
			}
			started := false
			reaped := make(chan struct{})
			b.lifecycle.rt.Exec = sshTransportRunnerFunc(func(ctx context.Context, req LocalCommandRequest) (LocalCommandResult, error) {
				started = true
				if req.Args[len(req.Args)-1] != ":43210" {
					t.Errorf("proxy ignored persisted port: args=%q", req.Args)
				}
				mutate()
				fmt.Fprintln(req.Stdout, "Forwarding from 127.0.0.1:12345 -> 43210")
				<-ctx.Done()
				close(reaped)
				return LocalCommandResult{}, ctx.Err()
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = b.ProxySSH(ctx, claim.LeaseID, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil {
				t.Fatalf("%s forwarding accepted changed %s identity", phase, identity)
			}
			if started != (phase == "after") {
				t.Fatalf("%s forwarding: started=%t", phase, started)
			}
			if started {
				select {
				case <-reaped:
				default:
					t.Fatal("post-start UID rejection leaked forwarding process")
				}
			}
		})
	}
}

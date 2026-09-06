package agentsandbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	core "github.com/openclaw/crabbox/internal/cli"
	"golang.org/x/crypto/ssh"
)

func bootstrapTestPublicKey(t *testing.T, seed byte) string {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)).Public()
	public, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
}

func bootstrapTestOutput(key, port string) string {
	return sshUserMarker + "root\n" + sshHostKeyMarker + key + "\n" + sshPortMarker + port + "\n"
}

func TestParseSSHBootstrapOutputPinsOnlyCompleteIdentity(t *testing.T) {
	key := bootstrapTestPublicKey(t, 1)
	valid := bootstrapTestOutput(key, "43210")
	for _, port := range []string{"1024", "43210", "65535"} {
		info, err := parseSSHBootstrapOutput(bootstrapTestOutput(key, port))
		if err != nil || info.User != "root" || info.HostKey != key || info.Port != port {
			t.Fatalf("identity=%#v error=%v", info, err)
		}
	}
	invalid := map[string]string{
		"empty":             "",
		"missing host key":  sshUserMarker + "root\n" + sshPortMarker + "43210\n",
		"missing port":      sshUserMarker + "root\n" + sshHostKeyMarker + key + "\n",
		"duplicate user":    sshUserMarker + "root\n" + valid,
		"duplicate port":    valid + sshPortMarker + "43210\n",
		"empty user":        strings.Replace(valid, "root", "", 1),
		"nonroot":           strings.Replace(valid, "root", "user", 1),
		"reordered":         sshPortMarker + "43210\n" + sshUserMarker + "root\n" + sshHostKeyMarker + key + "\n",
		"extra output":      valid + "unexpected\n",
		"blank line":        valid + "\n",
		"invalid key":       bootstrapTestOutput("ssh-ed25519 invalid", "43210"),
		"authorized option": bootstrapTestOutput("restrict "+key, "43210"),
		"multiple keys":     bootstrapTestOutput(key+"\n"+key, "43210"),
		"carriage return":   strings.ReplaceAll(valid, "\n", "\r\n"),
	}
	for _, port := range []string{"", "0", "1023", "65536", "043210", "+43210", "43210 ", "43210\r", "ssh", "43210;true"} {
		invalid["port "+fmt.Sprintf("%q", port)] = bootstrapTestOutput(key, port)
	}
	for name, output := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSSHBootstrapOutput(output); err == nil {
				t.Fatal("invalid initializer output accepted")
			}
		})
	}
}

func TestSSHInitializationInputValidatesPublicOnlyProtocol(t *testing.T) {
	key := bootstrapTestPublicKey(t, 1)
	hostKey := bootstrapTestPublicKey(t, 2)
	for _, endpoint := range [][2]string{{"", ""}, {hostKey, "1024"}, {hostKey, "65535"}} {
		data, err := sshInitializationInput("asbx_test-1", key, endpoint[0], endpoint[1])
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]string
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"lease_id": "asbx_test-1", "public_key": key, "expected_host_key": endpoint[0], "expected_port": endpoint[1]}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("initializer request=%#v want=%#v", got, want)
		}
	}
	for _, id := range []string{"", "../other", "lease;touch marker", "lease\nmarker", "lease with spaces", "lease\x00", strings.Repeat("a", 129)} {
		if _, err := sshInitializationInput(id, key, "", ""); err == nil {
			t.Fatalf("accepted unsafe lease ID %q", id)
		}
	}
	for _, invalid := range []string{"", "not a key", key + "\n" + key, "command=evil " + key, key + "\r\nother"} {
		if _, err := sshInitializationInput("asbx_test", invalid, "", ""); err == nil {
			t.Fatalf("accepted unsafe authorized key %q", invalid)
		}
		if _, err := sshInitializationInput("asbx_test", key, invalid, "43210"); err == nil {
			t.Fatalf("accepted unsafe/incomplete pinned key %q", invalid)
		}
	}
	for _, endpoint := range [][2]string{{hostKey, ""}, {"", "43210"}, {hostKey, "1023"}, {hostKey, "65536"}, {hostKey, "043210"}, {hostKey, "-1"}, {hostKey, "43210\n"}} {
		if _, err := sshInitializationInput("asbx_test", key, endpoint[0], endpoint[1]); err == nil {
			t.Fatalf("accepted invalid pinned endpoint %#v", endpoint)
		}
	}
}

// This fake models the wire protocol rather than emitting initializer output for
// every exec. The ELF upload is consumed but never run, and no root is required.
type sshBootstrapTestClient struct {
	*fakeKubernetesClient
	architecture      string
	output            string
	phases            []string
	request           sshInitializationRequest
	requestData       []byte
	uploadHeader      [4]byte
	uploadBytes       int64
	initializerPath   string
	probeOutput       string
	probeErr          error
	probe             func() error
	during            func() error
	upload            func(podExecRequest) error
	initializeErr     error
	cleanupErr        error
	cleanupContextErr error
}

func (c *sshBootstrapTestClient) Exec(ctx context.Context, req podExecRequest) error {
	c.execs = append(c.execs, req)
	switch {
	case reflect.DeepEqual(req.Command, []string{"uname", "-m"}):
		c.phases = append(c.phases, "architecture")
		architecture := c.architecture
		if architecture == "" {
			architecture = "x86_64"
		}
		_, err := io.WriteString(req.Stdout, architecture+"\n")
		return err
	case len(req.Command) == 5 && req.Command[0] == "sh" && req.Command[1] == "-c" && req.Command[3] == "crabbox-seed-probe" && req.Command[4] == sshSeedInitializer:
		c.phases = append(c.phases, "probe")
		if req.Stdin != nil {
			return errors.New("seed probe received initializer or credentials")
		}
		if c.probe != nil {
			if err := c.probe(); err != nil {
				return err
			}
		}
		if c.probeErr != nil {
			return c.probeErr
		}
		output := c.probeOutput
		if output == "" {
			output = "CRABBOX_SEED_UNAVAILABLE\n"
		}
		_, err := io.WriteString(req.Stdout, output)
		return err
	case len(req.Command) == 3 && req.Command[0] == "sh" && req.Command[1] == "-c" && req.Stdin != nil:
		c.phases = append(c.phases, "upload")
		if c.upload != nil {
			return c.upload(req)
		}
		n, err := io.ReadFull(req.Stdin, c.uploadHeader[:])
		c.uploadBytes = int64(n)
		if err != nil {
			return err
		}
		rest, err := io.Copy(io.Discard, req.Stdin)
		c.uploadBytes += rest
		return err
	case len(req.Command) == 1 && (req.Command[0] == sshSeedInitializer || (strings.HasPrefix(req.Command[0], "/tmp/crabbox-init-") && strings.HasSuffix(req.Command[0], "/initialize"))):
		c.phases = append(c.phases, "initialize")
		c.initializerPath = req.Command[0]
		data, err := io.ReadAll(req.Stdin)
		if err != nil {
			return err
		}
		c.requestData = data
		if err := json.Unmarshal(data, &c.request); err != nil {
			return err
		}
		if c.during != nil {
			if err := c.during(); err != nil {
				return err
			}
		}
		if c.initializeErr != nil {
			return c.initializeErr
		}
		_, err = io.WriteString(req.Stdout, c.output)
		return err
	case len(req.Command) == 3 && req.Command[0] == "sh" && req.Command[1] == "-c" && req.Stdin == nil:
		c.phases = append(c.phases, "cleanup")
		c.cleanupContextErr = ctx.Err()
		return c.cleanupErr
	default:
		return fmt.Errorf("unexpected bootstrap exec: %q", req.Command)
	}
}

func newSSHBootstrapTestSetup(t *testing.T) (*backend, *sshBootstrapTestClient, sandboxReadiness, LeaseClaim) {
	t.Helper()
	cfg := testAgentSandboxConfig(t)
	cfg.Provider = sshProviderName
	fake := readyFakeClient(cfg)
	b := testBackend(cfg, fake, nil, nil)
	_, _, _, ready, claim, unlock, err := b.createClaim(t.Context(), fake, "ssh-bootstrap", Repo{Root: t.TempDir()}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
	client := &sshBootstrapTestClient{fakeKubernetesClient: fake, output: bootstrapTestOutput(bootstrapTestPublicKey(t, 1), "43210")}
	return b, client, ready, claim
}

func TestInitializeSSHArchitectureSelection(t *testing.T) {
	for _, architecture := range []string{"x86_64", "amd64", "arm64", "aarch64", "riscv64"} {
		t.Run(architecture, func(t *testing.T) {
			b, client, ready, claim := newSSHBootstrapTestSetup(t)
			client.architecture = architecture
			input, err := sshInitializationInput(claim.LeaseID, bootstrapTestPublicKey(t, 2), "", "")
			if err != nil {
				t.Fatal(err)
			}
			info, err := b.initializeSSH(t.Context(), client, ready, input)
			if architecture != "x86_64" && architecture != "amd64" {
				if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("does not support architecture %q", architecture)) || !strings.Contains(err.Error(), "only amd64 (x86_64) is supported") {
					t.Fatalf("unsupported architecture error=%v", err)
				}
				if !reflect.DeepEqual(client.phases, []string{"architecture"}) || client.uploadBytes != 0 {
					t.Fatalf("unsupported architecture reached bootstrap: phases=%v uploaded=%d", client.phases, client.uploadBytes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(client.phases, []string{"architecture", "probe", "upload", "initialize", "cleanup"}) {
				t.Fatalf("bootstrap phases=%v", client.phases)
			}
			if client.uploadHeader != [4]byte{0x7f, 'E', 'L', 'F'} || client.uploadBytes <= 4 {
				t.Fatalf("initializer upload is not a decoded ELF: header=%x size=%d", client.uploadHeader, client.uploadBytes)
			}
			if info.User != "root" || info.HostKey != bootstrapTestPublicKey(t, 1) || info.Port != "43210" {
				t.Fatalf("bootstrap identity=%#v", info)
			}
		})
	}
}

func TestPrepareSSHPublishesPinnedIdentityAndFailsClosed(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	for _, scenario := range []string{"publish", "reuse", "host key changed", "port changed", "claim changed", "seed publish", "seed reuse", "seed host key changed", "seed port changed", "seed claim changed"} {
		t.Run(scenario, func(t *testing.T) {
			b, client, ready, claim := newSSHBootstrapTestSetup(t)
			seeded := strings.HasPrefix(scenario, "seed ")
			scenario = strings.TrimPrefix(scenario, "seed ")
			if seeded {
				digest, err := sshInitializerSHA256()
				if err != nil {
					t.Fatal(err)
				}
				client.probeOutput = digest + "  " + sshSeedInitializer + "\n"
			}
			key := bootstrapTestPublicKey(t, 1)
			keyPath, publicKey, err := core.EnsureTestboxKey(claim.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			trustPath := filepath.Join(filepath.Dir(keyPath), "known_hosts")
			var priorTrust []byte
			if scenario == "reuse" || scenario == "host key changed" || scenario == "port changed" {
				labels := cloneStringMap(claim.Labels)
				labels[claimLabelSSHUser] = "root"
				labels[claimLabelSSHHostKey] = key
				labels[claimLabelSSHPort] = "43210"
				claim, err = updateLeaseClaimLabelsIfUnchanged(claim.LeaseID, claim, labels)
				if err != nil {
					t.Fatal(err)
				}
				target, err := b.sshTarget(claim)
				if err != nil {
					t.Fatal(err)
				}
				if err := core.PrepareLeaseSSHTrust(&target, claim.LeaseID); err != nil {
					t.Fatal(err)
				}
				priorTrust, err = os.ReadFile(trustPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "host key changed" {
				client.output = bootstrapTestOutput(bootstrapTestPublicKey(t, 2), "43210")
			}
			if scenario == "port changed" {
				client.output = bootstrapTestOutput(key, "43211")
			}
			if scenario == "claim changed" {
				client.during = func() error {
					labels := cloneStringMap(claim.Labels)
					labels["concurrent_change"] = "preserved"
					_, err := updateLeaseClaimLabelsIfUnchanged(claim.LeaseID, claim, labels)
					return err
				}
			}
			updated, prepareErr := b.prepareSSH(t.Context(), client, ready, claim)
			wantPhases := []string{"architecture", "probe", "upload", "initialize", "cleanup"}
			if seeded {
				wantPhases = []string{"architecture", "probe", "initialize"}
			}
			if !reflect.DeepEqual(client.phases, wantPhases) {
				t.Fatalf("bootstrap phases=%v error=%v", client.phases, prepareErr)
			}
			if seeded && (client.uploadBytes != 0 || client.initializerPath != sshSeedInitializer) {
				t.Fatalf("seed path uploaded or used wrong executable: bytes=%d path=%s", client.uploadBytes, client.initializerPath)
			}
			if !seeded && (client.uploadHeader != [4]byte{0x7f, 'E', 'L', 'F'} || client.uploadBytes <= 4) {
				t.Fatalf("initializer upload is not a decoded ELF: header=%x size=%d", client.uploadHeader, client.uploadBytes)
			}
			wantRequest := sshInitializationRequest{LeaseID: claim.LeaseID, PublicKey: strings.TrimSpace(publicKey), ExpectedHostKey: claim.Labels[claimLabelSSHHostKey], ExpectedPort: claim.Labels[claimLabelSSHPort]}
			if client.request != wantRequest {
				t.Fatalf("initializer request=%#v want=%#v", client.request, wantRequest)
			}
			privateKey, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(client.requestData, privateKey) || bytes.Contains(client.requestData, []byte("PRIVATE KEY")) {
				t.Fatal("initializer request contains client private key")
			}
			for _, req := range client.execs {
				if strings.Contains(strings.Join(req.Command, " "), strings.TrimSpace(publicKey)) {
					t.Fatal("lease key was put in remote command arguments rather than stdin")
				}
			}
			stored, err := readLeaseClaim(claim.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			trust, trustErr := os.ReadFile(trustPath)
			if scenario == "publish" || scenario == "reuse" {
				if prepareErr != nil || updated.Labels[claimLabelSSHUser] != "root" || updated.Labels[claimLabelSSHHostKey] != key || updated.Labels[claimLabelSSHPort] != "43210" || stored.Labels[claimLabelSSHHostKey] != key || stored.Labels[claimLabelSSHPort] != "43210" {
					t.Fatalf("updated=%#v stored=%#v error=%v", updated.Labels, stored.Labels, prepareErr)
				}
				if trustErr != nil || strings.TrimSpace(string(trust)) != claim.LeaseID+" "+key {
					t.Fatalf("prepared known_hosts=%q error=%v", trust, trustErr)
				}
			} else {
				if prepareErr == nil {
					t.Fatal("changed identity/port/claim was accepted")
				}
				if priorTrust != nil {
					if trustErr != nil || !bytes.Equal(trust, priorTrust) {
						t.Fatalf("failed bootstrap replaced host trust: %q error=%v", trust, trustErr)
					}
				} else if !os.IsNotExist(trustErr) {
					t.Fatalf("failed bootstrap installed host trust: %q error=%v", trust, trustErr)
				}
				for _, label := range []string{claimLabelSSHUser, claimLabelSSHHostKey, claimLabelSSHPort} {
					if stored.Labels[label] != claim.Labels[label] {
						t.Fatalf("failure replaced pinned %s", label)
					}
				}
				if scenario == "claim changed" && stored.Labels["concurrent_change"] != "preserved" {
					t.Fatal("bootstrap overwrote a concurrent claim update")
				}
			}
		})
	}
}

func TestInitializeSSHSeedSelection(t *testing.T) {
	reader, err := openSSHInitializer("amd64")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x  %s\n", hash.Sum(nil), sshSeedInitializer)
	for _, scenario := range []string{"match", "mismatch", "missing", "unsupported", "malformed", "runtime failure", "invalid output", "transport failure", "remote failure", "canceled probe"} {
		t.Run(scenario, func(t *testing.T) {
			b, client, ready, claim := newSSHBootstrapTestSetup(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input, err := sshInitializationInput(claim.LeaseID, bootstrapTestPublicKey(t, 2), "", "")
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("seed operation failed")
			client.probeOutput = checksum
			wantPhases := []string{"architecture", "probe", "initialize"}
			var wantErr error
			fallback := false
			switch scenario {
			case "mismatch", "missing", "unsupported", "malformed":
				fallback = true
				wantPhases = []string{"architecture", "probe", "upload", "initialize", "cleanup"}
				client.probeOutput = "CRABBOX_SEED_UNAVAILABLE\n"
				if scenario == "mismatch" {
					client.probeOutput = strings.Repeat("0", 64) + "  " + sshSeedInitializer + "\n"
				} else if scenario == "malformed" {
					client.probeOutput = checksum + "unexpected extra output\n"
				}
			case "runtime failure":
				client.initializeErr, wantErr = failure, failure
			case "invalid output":
				client.output = "not endpoint metadata\n"
			case "transport failure", "remote failure", "canceled probe":
				wantPhases = []string{"architecture", "probe"}
				if scenario == "transport failure" {
					client.probeErr, wantErr = failure, failure
				} else if scenario == "remote failure" {
					client.probeErr = testExitError{code: 1}
					wantErr = client.probeErr
				} else {
					client.probe = func() error { cancel(); return nil }
					wantErr = context.Canceled
				}
			}
			info, err := b.initializeSSH(ctx, client, ready, input)
			if wantErr != nil {
				if !errors.Is(err, wantErr) {
					t.Fatalf("error=%v want=%v", err, wantErr)
				}
			} else if scenario == "invalid output" {
				if err == nil || !strings.Contains(err.Error(), "unexpected or duplicate output") {
					t.Fatalf("invalid seed output accepted: %v", err)
				}
			} else if err != nil || info.User != "root" || info.HostKey != bootstrapTestPublicKey(t, 1) || info.Port != "43210" {
				t.Fatalf("identity=%#v error=%v", info, err)
			}
			if !reflect.DeepEqual(client.phases, wantPhases) {
				t.Fatalf("phases=%v want=%v", client.phases, wantPhases)
			}
			if fallback {
				if client.uploadBytes <= 4 || client.uploadHeader != [4]byte{0x7f, 'E', 'L', 'F'} || !strings.HasPrefix(client.initializerPath, "/tmp/crabbox-init-") {
					t.Fatalf("fallback did not upload executable: bytes=%d path=%s", client.uploadBytes, client.initializerPath)
				}
			} else if client.uploadBytes != 0 || (len(wantPhases) == 3 && client.initializerPath != sshSeedInitializer) {
				t.Fatalf("seed path uploaded or used wrong executable: bytes=%d path=%s", client.uploadBytes, client.initializerPath)
			}
			if client.initializerPath != "" && !bytes.Equal(client.requestData, input) {
				t.Fatal("seed selection changed per-lease initialization request")
			}
		})
	}
}

func TestSSHSeedProbeReadsExecutableWithoutRunningIt(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum unavailable")
	}
	for _, scenario := range []string{"executable", "symlink", "missing", "not executable", "unsupported checksum", "failed checksum"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			seed := filepath.Join(dir, "initialize")
			marker := filepath.Join(dir, "executed")
			data := []byte("#!/bin/sh\nprintf executed > " + shellQuote(marker) + "\n")
			if scenario != "missing" {
				if err := os.WriteFile(seed, data, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "symlink" {
				link := filepath.Join(dir, "seed-link")
				if err := os.Symlink(seed, link); err != nil {
					t.Fatal(err)
				}
				seed = link
			} else if scenario == "not executable" {
				if err := os.Chmod(seed, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(sh, "-c", sshSeedProbe, "crabbox-seed-probe", seed)
			if scenario == "unsupported checksum" || scenario == "failed checksum" {
				cmd.Env = append(os.Environ(), "PATH="+dir)
				if scenario == "failed checksum" {
					if err := os.WriteFile(filepath.Join(dir, "sha256sum"), []byte("#!"+sh+"\nexit 1\n"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			output, err := cmd.CombinedOutput()
			want := "CRABBOX_SEED_UNAVAILABLE\n"
			if scenario == "executable" || scenario == "symlink" {
				want = fmt.Sprintf("%x  %s\n", sha256.Sum256(data), seed)
			}
			if err != nil || string(output) != want {
				t.Fatalf("probe=%q error=%v want=%q", output, err, want)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("probe executed image-provided initializer: %v", err)
			}
		})
	}
}

func TestInitializeSSHRejectsUnsupportedArchitectureBeforeUpload(t *testing.T) {
	b, client, ready, _ := newSSHBootstrapTestSetup(t)
	client.architecture = "riscv64"
	_, err := b.initializeSSH(t.Context(), client, ready, nil)
	if err == nil || !strings.Contains(err.Error(), "riscv64") {
		t.Fatalf("unsupported architecture error=%v", err)
	}
	if !reflect.DeepEqual(client.phases, []string{"architecture"}) {
		t.Fatalf("unsupported architecture triggered mutations: %v", client.phases)
	}
}

func TestInitializeSSHUploadFailureDoesNotCleanUnownedPath(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	b, client, ready, _ := newSSHBootstrapTestSetup(t)
	// Execute only the upload shell, rebasing its random path to a test-owned
	// existing directory. A failed mkdir must not install a destructive trap.
	dir := filepath.Join(t.TempDir(), "already-exists")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "initialize")
	original := []byte("pre-existing file must survive")
	if err := os.WriteFile(marker, original, 0o600); err != nil {
		t.Fatal(err)
	}
	pathPattern := regexp.MustCompile(`/tmp/crabbox-init-[a-f0-9]{32}`)
	client.upload = func(req podExecRequest) error {
		paths := pathPattern.FindAllString(req.Command[2], -1)
		if len(paths) == 0 {
			t.Fatal("upload did not address a private temporary path")
		}
		for _, path := range paths {
			if path != paths[0] {
				t.Fatal("upload addressed multiple private paths")
			}
		}
		command := strings.ReplaceAll(req.Command[2], paths[0], filepath.ToSlash(dir))
		cmd := exec.Command(sh, "-c", command)
		cmd.Stdin = req.Stdin
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("upload unexpectedly accepted an existing path: %s", output)
		}
		return err
	}
	_, err = b.initializeSSH(t.Context(), client, ready, nil)
	if err == nil || !strings.Contains(err.Error(), "upload static initializer") {
		t.Fatalf("upload failure error=%v", err)
	}
	if !reflect.DeepEqual(client.phases, []string{"architecture", "probe", "upload"}) {
		t.Fatalf("failed upload initialized or cleaned an unowned path: %v", client.phases)
	}
	got, err := os.ReadFile(marker)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("upload changed pre-existing file: %q error=%v", got, err)
	}
}

func TestPrepareSSHRejectsIncompletePinnedEndpointBeforeExec(t *testing.T) {
	key := bootstrapTestPublicKey(t, 1)
	for name, endpoint := range map[string]map[string]string{
		"user only":                    {claimLabelSSHUser: "root"},
		"key only":                     {claimLabelSSHHostKey: key},
		"port only":                    {claimLabelSSHPort: "43210"},
		"legacy endpoint without port": {claimLabelSSHUser: "root", claimLabelSSHHostKey: key},
		"nonroot":                      {claimLabelSSHUser: "other", claimLabelSSHHostKey: key, claimLabelSSHPort: "43210"},
		"invalid port":                 {claimLabelSSHUser: "root", claimLabelSSHHostKey: key, claimLabelSSHPort: "043210"},
	} {
		t.Run(name, func(t *testing.T) {
			b, client, ready, claim := newSSHBootstrapTestSetup(t)
			labels := cloneStringMap(claim.Labels)
			for key, value := range endpoint {
				labels[key] = value
			}
			claim.Labels = labels
			if _, err := b.prepareSSH(t.Context(), client, ready, claim); err == nil {
				t.Fatal("incomplete or invalid pinned endpoint accepted")
			}
			if len(client.phases) != 0 {
				t.Fatalf("invalid metadata triggered remote execution: %v", client.phases)
			}
		})
	}
}

func TestInitializeSSHAlwaysCleansOwnedUploadAndReportsCleanupFailure(t *testing.T) {
	for _, scenario := range []string{"initializer failure", "invalid output", "cleanup failure", "canceled initializer"} {
		t.Run(scenario, func(t *testing.T) {
			b, client, ready, _ := newSSHBootstrapTestSetup(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			initializeErr := errors.New("initializer rejected existing tool")
			cleanupErr := errors.New("temporary upload removal failed")
			switch scenario {
			case "initializer failure":
				client.initializeErr = initializeErr
				client.cleanupErr = cleanupErr
			case "invalid output":
				client.output = "not endpoint metadata\n"
			case "cleanup failure":
				client.cleanupErr = cleanupErr
			case "canceled initializer":
				client.during = func() error { cancel(); return context.Canceled }
			}
			_, err := b.initializeSSH(ctx, client, ready, []byte(`{}`))
			if err == nil {
				t.Fatal("initializer/cleanup failure was ignored")
			}
			if !reflect.DeepEqual(client.phases, []string{"architecture", "probe", "upload", "initialize", "cleanup"}) || client.cleanupContextErr != nil {
				t.Fatalf("owned upload was not cleaned with live context: phases=%v context=%v", client.phases, client.cleanupContextErr)
			}
			if client.initializeErr != nil && !errors.Is(err, initializeErr) {
				t.Fatalf("initializer error lost: %v", err)
			}
			if client.cleanupErr != nil && !errors.Is(err, cleanupErr) {
				t.Fatalf("cleanup error lost: %v", err)
			}
			if scenario == "canceled initializer" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error lost: %v", err)
			}
		})
	}
}

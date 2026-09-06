//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestInitializationRequestIdentityContract(t *testing.T) {
	public, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	encodedKey, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	base := `"lease_id":"cbx_example","public_key":` + string(encodedKey)
	tests := []struct {
		name, data string
		valid      bool
	}{
		{"new lease", `{` + base + `}`, true},
		{"pinned lease", `{` + base + `,"expected_host_key":` + string(encodedKey) + `,"expected_port":"23456"}`, true},
		{"duplicate lease", `{` + base + `,"lease_id":"other"}`, false},
		{"null pin", `{` + base + `,"expected_host_key":null}`, false},
		{"unknown setting", `{` + base + `,"replace_existing":true}`, false},
		{"trailing object", `{` + base + `} {}`, false},
		{"traversal", `{"lease_id":"../other","public_key":` + string(encodedKey) + `}`, false},
		{"key without port", `{` + base + `,"expected_host_key":` + string(encodedKey) + `}`, false},
		{"port without key", `{` + base + `,"expected_port":"23456"}`, false},
		{"port leading zero", `{` + base + `,"expected_host_key":` + string(encodedKey) + `,"expected_port":"023456"}`, false},
		{"privileged port", `{` + base + `,"expected_host_key":` + string(encodedKey) + `,"expected_port":"22"}`, false},
		{"key options", `{"lease_id":"cbx_example","public_key":"no-pty ` + key + `"}`, false},
		{"second key line", `{"lease_id":"cbx_example","public_key":"` + key + `\n` + key + `"}`, false},
		{"oversized input", `{` + base + `,"expected_port":"` + strings.Repeat("1", 16384) + `"}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := decodeRequest(strings.NewReader(test.data))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t, error=%v", test.valid, err)
			}
			if test.valid && (parsed.LeaseID != "cbx_example" || parsed.PublicKey != key) {
				t.Fatalf("unexpected parsed identity: %+v", parsed)
			}
		})
	}
}

func TestHostKeyCanonicalizationPreservesKeyNotComment(t *testing.T) {
	public, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	actual, err := canonicalKey(key + " root@container")
	if err != nil {
		t.Fatal(err)
	}
	if actual != key {
		t.Fatalf("canonical key=%q, want %q", actual, key)
	}
	if _, err := canonicalKey(`command="echo denied" ` + key); err == nil {
		t.Fatal("accepted command option on lease public key")
	}
}

func TestPreseededRuntimeAbsentPreservesUploadFallback(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "initialize")
	if err := os.WriteFile(executable, []byte("initializer"), 0555); err != nil {
		t.Fatal(err)
	}
	root, err := preseededRuntime(executable)
	if err != nil || root != "" {
		t.Fatalf("missing sibling should select upload fallback, got %q, %v", root, err)
	}
}

func TestPreseededRuntimeVerification(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runtime ownership verification requires root")
	}
	// /tmp is intentionally not an acceptable ancestor for an image runtime.
	base, err := os.MkdirTemp("/var/lib", "crabbox-seed-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	var archive bytes.Buffer
	z := gzip.NewWriter(&archive)
	w := tar.NewWriter(z)
	for _, h := range []*tar.Header{
		{Name: "bin", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "bin/tool", Typeflag: tar.TypeReg, Mode: 0755, Size: 4},
		{Name: "bin/alias", Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: "tool"},
	} {
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := w.Write([]byte("tool")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	original := payload
	payload = archive.Bytes()
	t.Cleanup(func() { payload = original })
	for _, name := range []string{"immutable", "changed content", "missing file", "writable file", "writable ancestor", "foreign owner", "payload symlink", "changed alias"} {
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(base, strings.ReplaceAll(name, " ", "-"))
			root := filepath.Join(directory, "payload")
			if err := os.MkdirAll(root, 0755); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(directory, "initialize")
			if err := os.WriteFile(executable, []byte("initializer"), 0555); err != nil {
				t.Fatal(err)
			}
			if err := unpackRuntime(root, false); err != nil {
				t.Fatal(err)
			}
			tool := filepath.Join(root, "bin/tool")
			var changeErr error
			switch name {
			case "immutable":
				for _, path := range []string{directory, root, filepath.Join(root, "bin")} {
					if err := os.Chmod(path, 0555); err != nil {
						t.Fatal(err)
					}
				}
			case "changed content":
				changeErr = os.WriteFile(tool, []byte("evil"), 0555)
			case "missing file":
				changeErr = os.Remove(tool)
			case "writable file":
				changeErr = os.Chmod(tool, 0755)
			case "writable ancestor":
				changeErr = os.Chmod(directory, 0775)
			case "foreign owner":
				changeErr = os.Chown(root, 12345, -1)
			case "payload symlink":
				if err := os.Rename(root, root+"-elsewhere"); err != nil {
					t.Fatal(err)
				}
				changeErr = os.Symlink(root+"-elsewhere", root)
			case "changed alias":
				alias := filepath.Join(root, "bin/alias")
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				changeErr = os.Symlink("../bin/tool", alias)
			}
			if changeErr != nil {
				t.Fatal(changeErr)
			}
			entrypoint := filepath.Join(base, "entry-"+strings.ReplaceAll(name, " ", "-"))
			if err := os.Symlink(executable, entrypoint); err != nil {
				t.Fatal(err)
			}
			selected, err := preseededRuntime(entrypoint)
			if name == "immutable" {
				if err != nil || selected != root {
					t.Fatalf("immutable resolved sibling rejected: %q, %v", selected, err)
				}
				info, err := os.Stat(root)
				if err != nil || info.Mode().Perm() != 0555 {
					t.Fatalf("seed directory permissions changed: %v", err)
				}
			} else if err == nil || selected != "" {
				t.Fatalf("invalid seed accepted or silently skipped: %q, %v", selected, err)
			}
		})
	}
}

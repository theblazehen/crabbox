//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/json"
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

package sshclient

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
)

func TestCopyWithProgressReportsFinalDoneEvent(t *testing.T) {
	src := bytes.NewBufferString("hello")
	var dst bytes.Buffer
	var events []UploadProgress

	err := copyWithProgress(src, &dst, "local.bin", "/tmp/remote.bin", 5, func(progress UploadProgress) {
		events = append(events, progress)
	})
	if err != nil {
		t.Fatalf("copyWithProgress returned error: %v", err)
	}
	if got := dst.String(); got != "hello" {
		t.Fatalf("dst = %q, want %q", got, "hello")
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want %d", len(events), 2)
	}

	first := events[0]
	if first.Done {
		t.Fatal("first progress event marked done unexpectedly")
	}
	if first.Sent != 5 || first.Total != 5 {
		t.Fatalf("first progress = %+v, want Sent=5 Total=5", first)
	}

	last := events[len(events)-1]
	if !last.Done {
		t.Fatal("last progress event should be marked done")
	}
	if last.Sent != 5 || last.Total != 5 {
		t.Fatalf("last progress = %+v, want Sent=5 Total=5", last)
	}
	if last.LocalPath != "local.bin" || last.RemotePath != "/tmp/remote.bin" {
		t.Fatalf("last progress paths = (%q, %q), want (%q, %q)", last.LocalPath, last.RemotePath, "local.bin", "/tmp/remote.bin")
	}
}

func TestDialReturnsKnownHostsError(t *testing.T) {
	origHostKey := hostKeyCallbackFn
	defer func() {
		hostKeyCallbackFn = origHostKey
	}()

	t.Setenv("USER", "local-user")
	t.Setenv("SDUP_SSH_PASSWORD", "secret")

	wantErr := errors.New("known hosts unavailable")
	hostKeyCallbackFn = func() (ssh.HostKeyCallback, error) {
		return nil, wantErr
	}

	_, err := Dial("prod", Options{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Dial error = %v, want %v", err, wantErr)
	}
}

func TestUseAgentWithSocketDoesNotMutateSSHAuthSock(t *testing.T) {
	origDial := dialAgentSocketFn
	defer func() {
		dialAgentSocketFn = origDial
	}()

	t.Setenv("SSH_AUTH_SOCK", "/tmp/original-agent.sock")

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	dialAgentSocketFn = func(network, address string) (net.Conn, error) {
		if network != "unix" {
			t.Fatalf("network = %q, want %q", network, "unix")
		}
		if address != "/tmp/custom-agent.sock" {
			t.Fatalf("address = %q, want %q", address, "/tmp/custom-agent.sock")
		}
		return client, nil
	}

	auth, err := useAgentWithSocket("/tmp/custom-agent.sock")
	if err != nil {
		t.Fatalf("useAgentWithSocket returned error: %v", err)
	}
	if len(auth) == 0 {
		t.Fatal("useAgentWithSocket returned empty auth")
	}
	if got := os.Getenv("SSH_AUTH_SOCK"); got != "/tmp/original-agent.sock" {
		t.Fatalf("SSH_AUTH_SOCK = %q, want %q", got, "/tmp/original-agent.sock")
	}
}

func TestDialUsesInjectedConnFactory(t *testing.T) {
	origHostKey := hostKeyCallbackFn
	origConn := newConnFn
	defer func() {
		hostKeyCallbackFn = origHostKey
		newConnFn = origConn
	}()

	t.Setenv("USER", "local-user")
	t.Setenv("SDUP_SSH_PASSWORD", "secret")

	hostKeyCallbackFn = func() (ssh.HostKeyCallback, error) {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	called := false
	newConnFn = func(config *goph.Config) (*goph.Client, error) {
		called = true
		return nil, errors.New("boom")
	}

	_, err := Dial("prod", Options{})
	if err == nil {
		t.Fatal("Dial returned nil error")
	}
	if !called {
		t.Fatal("newConnFn was not called")
	}
}

func TestDialCanIgnoreKnownHostsWhenRequested(t *testing.T) {
	origHostKey := hostKeyCallbackFn
	origConn := newConnFn
	defer func() {
		hostKeyCallbackFn = origHostKey
		newConnFn = origConn
	}()

	t.Setenv("USER", "local-user")
	t.Setenv("SDUP_SSH_PASSWORD", "secret")

	hostKeyCalled := false
	hostKeyCallbackFn = func() (ssh.HostKeyCallback, error) {
		hostKeyCalled = true
		return nil, errors.New("should not be called")
	}

	connCalled := false
	newConnFn = func(config *goph.Config) (*goph.Client, error) {
		connCalled = true
		if config.Callback == nil {
			t.Fatal("config.Callback is nil")
		}
		return nil, errors.New("boom")
	}

	_, err := Dial("prod", Options{IgnoreKnownHosts: true})
	if err == nil {
		t.Fatal("Dial returned nil error")
	}
	if hostKeyCalled {
		t.Fatal("hostKeyCallbackFn should not be called when IgnoreKnownHosts is enabled")
	}
	if !connCalled {
		t.Fatal("newConnFn was not called")
	}
}

package main

import (
	"errors"
	"testing"

	"github.com/melbahja/goph"
)

func TestUpdateApplyConnectionOverrides(t *testing.T) {
	cfg := &HostConfig{User: "ubuntu", Port: 1000}
	portOverride := 22

	err := applyConnectionOverrides(cfg, "root", 2222, sshCLIOptions{Port: &portOverride})
	if err != nil {
		t.Fatalf("applyConnectionOverrides returned error: %v", err)
	}

	if cfg.User != "root" {
		t.Fatalf("user = %q, want %q", cfg.User, "root")
	}
	if cfg.Port != 22 {
		t.Fatalf("port = %d, want %d", cfg.Port, 22)
	}
}

func TestUpdateApplyConnectionOverridesAppliesRawOptionOverride(t *testing.T) {
	cfg := &HostConfig{User: "ubuntu", Port: 1000, Hostname: "prod"}

	err := applyConnectionOverrides(cfg, "root", 2222, sshCLIOptions{
		RawOptions: []string{"User=deploy", "Port=2200", "HostName=10.0.0.10"},
	})
	if err != nil {
		t.Fatalf("applyConnectionOverrides returned error: %v", err)
	}

	if cfg.User != "deploy" {
		t.Fatalf("user = %q, want %q", cfg.User, "deploy")
	}
	if cfg.Port != 2200 {
		t.Fatalf("port = %d, want %d", cfg.Port, 2200)
	}
	if cfg.Hostname != "10.0.0.10" {
		t.Fatalf("hostname = %q, want %q", cfg.Hostname, "10.0.0.10")
	}
}

func TestSystemdUpdateSkipsSSHWhenLocalFileMissing(t *testing.T) {
	origResolve := resolveConnectionConfigFn
	origDial := dialSSHFn
	origDeploy := deploySystemdUpdateFn
	defer func() {
		resolveConnectionConfigFn = origResolve
		dialSSHFn = origDial
		deploySystemdUpdateFn = origDeploy
	}()

	resolveCalled := false
	dialCalled := false
	deployCalled := false

	resolveConnectionConfigFn = func(remoteHost string, sshOptions sshCLIOptions) (*HostConfig, error) {
		resolveCalled = true
		return &HostConfig{}, nil
	}
	dialSSHFn = func(cfg *HostConfig) (*goph.Client, error) {
		dialCalled = true
		return nil, errors.New("unexpected dial")
	}
	deploySystemdUpdateFn = func(client *goph.Client, localFile, remoteService string) error {
		deployCalled = true
		return nil
	}

	err := SystemdUpdate("/tmp/definitely-missing-sdup-binary", "api", "prod", sshCLIOptions{})
	if err == nil {
		t.Fatal("SystemdUpdate returned nil error for missing file")
	}
	if resolveCalled {
		t.Fatal("resolveConnectionConfig should not be called when local file is missing")
	}
	if dialCalled {
		t.Fatal("dialSSH should not be called when local file is missing")
	}
	if deployCalled {
		t.Fatal("deploySystemdUpdate should not be called when local file is missing")
	}
}

package main

import "testing"

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

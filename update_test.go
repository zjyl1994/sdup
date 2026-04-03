package main

import "testing"

func TestUpdateApplyConnectionOverrides(t *testing.T) {
	cfg := &HostConfig{User: "ubuntu", Port: 1000}

	applyConnectionOverrides(cfg, "root", 2222, 22)

	if cfg.User != "root" {
		t.Fatalf("user = %q, want %q", cfg.User, "root")
	}
	if cfg.Port != 22 {
		t.Fatalf("port = %d, want %d", cfg.Port, 22)
	}
}

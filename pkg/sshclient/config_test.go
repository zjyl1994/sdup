package sshclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConnectionConfigUsesSSHConfigAlias(t *testing.T) {
	homeDir := writeSSHConfigForTest(t, `
Host prod
    HostName 10.10.10.10
    User deploy
    Port 2200
    IdentityFile ~/.ssh/prod_ed25519
    IdentitiesOnly yes
    IdentityAgent ~/.ssh/agent.sock
`)

	cfg, err := resolveConnectionConfig("prod", Options{})
	if err != nil {
		t.Fatalf("resolveConnectionConfig returned error: %v", err)
	}

	if cfg.Hostname != "10.10.10.10" {
		t.Fatalf("Hostname = %q, want %q", cfg.Hostname, "10.10.10.10")
	}
	if cfg.User != "deploy" {
		t.Fatalf("User = %q, want %q", cfg.User, "deploy")
	}
	if cfg.Port != 2200 {
		t.Fatalf("Port = %d, want %d", cfg.Port, 2200)
	}
	if len(cfg.IdentityFiles) == 0 || cfg.IdentityFiles[0] != filepath.Join(homeDir, ".ssh", "prod_ed25519") {
		t.Fatalf("IdentityFiles[0] = %q, want %q", firstIdentity(cfg.IdentityFiles), filepath.Join(homeDir, ".ssh", "prod_ed25519"))
	}
	if !cfg.IdentitiesOnly {
		t.Fatalf("IdentitiesOnly = false, want true")
	}
	if cfg.AgentSocket != filepath.Join(homeDir, ".ssh", "agent.sock") {
		t.Fatalf("AgentSocket = %q, want %q", cfg.AgentSocket, filepath.Join(homeDir, ".ssh", "agent.sock"))
	}
}

func TestResolveConnectionConfigPortPrecedence(t *testing.T) {
	writeSSHConfigForTest(t, `
Host prod
    HostName 10.10.10.10
    Port 2200
`)

	cfg, err := resolveConnectionConfig("prod:2300", Options{})
	if err != nil {
		t.Fatalf("resolveConnectionConfig returned error: %v", err)
	}
	if cfg.Port != 2300 {
		t.Fatalf("Port = %d, want %d", cfg.Port, 2300)
	}

	cliPort := 2400
	cfg, err = resolveConnectionConfig("prod:2300", Options{Port: &cliPort})
	if err != nil {
		t.Fatalf("resolveConnectionConfig returned error: %v", err)
	}
	if cfg.Port != 2400 {
		t.Fatalf("Port = %d, want %d", cfg.Port, 2400)
	}
}

func TestResolveConnectionConfigDefaultsPortWhenUnset(t *testing.T) {
	writeSSHConfigForTest(t, `
Host prod
    HostName 10.10.10.10
`)

	cfg, err := resolveConnectionConfig("prod", Options{})
	if err != nil {
		t.Fatalf("resolveConnectionConfig returned error: %v", err)
	}
	if cfg.Port != defaultPort {
		t.Fatalf("Port = %d, want %d", cfg.Port, defaultPort)
	}
}

func TestResolveConnectionConfigUsesExplicitSSHConfigPath(t *testing.T) {
	configPath := writeStandaloneSSHConfigForTest(t, `
Host prod
    HostName 10.20.30.40
    User deploy
    Port 2201
`)

	cfg, err := resolveConnectionConfig("prod", Options{
		ConfigPath:    configPath,
		ConfigPathSet: true,
	})
	if err != nil {
		t.Fatalf("resolveConnectionConfig returned error: %v", err)
	}

	if cfg.Hostname != "10.20.30.40" {
		t.Fatalf("Hostname = %q, want %q", cfg.Hostname, "10.20.30.40")
	}
	if cfg.User != "deploy" {
		t.Fatalf("User = %q, want %q", cfg.User, "deploy")
	}
	if cfg.Port != 2201 {
		t.Fatalf("Port = %d, want %d", cfg.Port, 2201)
	}
}

func TestResolveConnectionConfigAppliesCLIIdentityAndOptions(t *testing.T) {
	homeDir := writeSSHConfigForTest(t, `
Host prod
    HostName 10.10.10.10
    User deploy
    Port 2200
    IdentityFile ~/.ssh/from-config
`)

	cfg, err := resolveConnectionConfig("prod", Options{
		IdentityFiles: []string{"~/.ssh/from-cli"},
		RawOptions: []string{
			"HostName=10.30.40.50",
			"User=override",
			"Port=2202",
			"IdentityFile=~/.ssh/from-option",
			"IdentitiesOnly=yes",
		},
	})
	if err != nil {
		t.Fatalf("resolveConnectionConfig returned error: %v", err)
	}

	if cfg.Hostname != "10.30.40.50" {
		t.Fatalf("Hostname = %q, want %q", cfg.Hostname, "10.30.40.50")
	}
	if cfg.User != "override" {
		t.Fatalf("User = %q, want %q", cfg.User, "override")
	}
	if cfg.Port != 2202 {
		t.Fatalf("Port = %d, want %d", cfg.Port, 2202)
	}
	wantIDs := []string{
		filepath.Join(homeDir, ".ssh", "from-cli"),
		filepath.Join(homeDir, ".ssh", "from-option"),
		filepath.Join(homeDir, ".ssh", "from-config"),
	}
	if len(cfg.IdentityFiles) < len(wantIDs) {
		t.Fatalf("IdentityFiles = %v, want prefix %v", cfg.IdentityFiles, wantIDs)
	}
	for i, want := range wantIDs {
		if cfg.IdentityFiles[i] != want {
			t.Fatalf("IdentityFiles[%d] = %q, want %q", i, cfg.IdentityFiles[i], want)
		}
	}
	if !cfg.IdentitiesOnly {
		t.Fatalf("IdentitiesOnly = false, want true")
	}
}

func TestResolveConnectionConfigErrorsForMissingExplicitConfig(t *testing.T) {
	_, err := resolveConnectionConfig("prod", Options{
		ConfigPath:    filepath.Join(t.TempDir(), "missing-config"),
		ConfigPathSet: true,
	})
	if err == nil {
		t.Fatalf("resolveConnectionConfig returned nil error, want error")
	}
}

func TestApplyConnectionOverridesAppliesRawOptionOverride(t *testing.T) {
	cfg := &hostConfig{User: "ubuntu", Port: 1000, Hostname: "prod"}

	err := applyConnectionOverrides(cfg, "root", 2222, Options{
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

func writeSSHConfigForTest(t *testing.T, content string) string {
	t.Helper()

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USER", "local-user")

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	return homeDir
}

func writeStandaloneSSHConfigForTest(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("USER", "local-user")

	configPath := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	return configPath
}

func firstIdentity(identityFiles []string) string {
	if len(identityFiles) == 0 {
		return ""
	}
	return identityFiles[0]
}

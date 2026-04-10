package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveInvocationOptionsUsesRepoConfig(t *testing.T) {
	repoDir := newRepoDirForTest(t)
	configPath := filepath.Join(repoDir, repoConfigFileName)
	if err := os.WriteFile(configPath, []byte(strings.Join([]string{
		"local_path = \"build/api\"",
		"remote_host = \"prod\"",
		"",
		"[ssh]",
		"config = \"ssh_config\"",
		"port = 2200",
		"ignore_known_hosts = true",
		"identity_files = [\"keys/id_ed25519\"]",
		"options = [\"User=deploy\", \"HostName=10.0.0.10\"]",
		"",
		"[deploy]",
		"log_lines = 7",
		"health_check_wait = \"9s\"",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	cwd := filepath.Join(repoDir, "nested", "dir")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	opts, repoCtx, err := resolveInvocationOptions(cliOptions{}, cwd)
	if err != nil {
		t.Fatalf("resolveInvocationOptions returned error: %v", err)
	}

	if repoCtx.rootDir != repoDir {
		t.Fatalf("rootDir = %q, want %q", repoCtx.rootDir, repoDir)
	}
	if got := opts.args[0]; got != filepath.Join(repoDir, "build", "api") {
		t.Fatalf("local_path = %q, want %q", got, filepath.Join(repoDir, "build", "api"))
	}
	if got := opts.args[1]; got != "prod" {
		t.Fatalf("remote_host = %q, want %q", got, "prod")
	}
	if opts.remoteService != "api" {
		t.Fatalf("remoteService = %q, want %q", opts.remoteService, "api")
	}
	if !opts.sshPortSet || opts.sshPort != 2200 {
		t.Fatalf("ssh port = (%v, %d), want (true, 2200)", opts.sshPortSet, opts.sshPort)
	}
	if !opts.sshConfigSet || opts.sshConfigPath != filepath.Join(repoDir, "ssh_config") {
		t.Fatalf("sshConfigPath = %q, want %q", opts.sshConfigPath, filepath.Join(repoDir, "ssh_config"))
	}
	if !opts.ignoreKnownHosts {
		t.Fatal("ignoreKnownHosts = false, want true")
	}
	if !equalStringSlices([]string(opts.identityFiles), []string{filepath.Join(repoDir, "keys", "id_ed25519")}) {
		t.Fatalf("identityFiles = %v", []string(opts.identityFiles))
	}
	if !equalStringSlices([]string(opts.sshOptions), []string{"User=deploy", "HostName=10.0.0.10"}) {
		t.Fatalf("sshOptions = %v", []string(opts.sshOptions))
	}
	if opts.deployment.logLines != 7 {
		t.Fatalf("logLines = %d, want %d", opts.deployment.logLines, 7)
	}
	if opts.deployment.healthCheckWait != 9*time.Second {
		t.Fatalf("healthCheckWait = %v, want %v", opts.deployment.healthCheckWait, 9*time.Second)
	}
}

func TestResolveInvocationOptionsCLIOverridesRepoConfig(t *testing.T) {
	repoDir := newRepoDirForTest(t)
	configPath := filepath.Join(repoDir, repoConfigFileName)
	if err := os.WriteFile(configPath, []byte(strings.Join([]string{
		"local_path = \"build/api\"",
		"remote_host = \"prod\"",
		"remote_service = \"api\"",
		"",
		"[deploy]",
		"log_lines = 3",
		"",
		"[ssh]",
		"port = 2200",
		"identity_files = [\"keys/from-config\"]",
		"options = [\"HostName=10.0.0.10\"]",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	parsed, err := parseCLIArgs([]string{"-p", "2201", "-n", "8", "-i", "~/.ssh/id_override", "-o", "HostName=10.0.0.20", "-s", "worker", "./bin/worker"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}

	opts, _, err := resolveInvocationOptions(parsed, repoDir)
	if err != nil {
		t.Fatalf("resolveInvocationOptions returned error: %v", err)
	}

	if got := opts.args[0]; got != "./bin/worker" {
		t.Fatalf("local_path = %q, want %q", got, "./bin/worker")
	}
	if got := opts.args[1]; got != "prod" {
		t.Fatalf("remote_host = %q, want %q", got, "prod")
	}
	if opts.remoteService != "worker" {
		t.Fatalf("remoteService = %q, want %q", opts.remoteService, "worker")
	}
	if !opts.sshPortSet || opts.sshPort != 2201 {
		t.Fatalf("ssh port = (%v, %d), want (true, 2201)", opts.sshPortSet, opts.sshPort)
	}
	if !equalStringSlices([]string(opts.identityFiles), []string{"~/.ssh/id_override", filepath.Join(repoDir, "keys", "from-config")}) {
		t.Fatalf("identityFiles = %v", []string(opts.identityFiles))
	}
	if !equalStringSlices([]string(opts.sshOptions), []string{"HostName=10.0.0.10", "HostName=10.0.0.20"}) {
		t.Fatalf("sshOptions = %v", []string(opts.sshOptions))
	}
	if opts.deployment.logLines != 8 {
		t.Fatalf("logLines = %d, want %d", opts.deployment.logLines, 8)
	}
	if opts.deployment.healthCheckWait != defaultHealthCheckWait {
		t.Fatalf("healthCheckWait = %v, want %v", opts.deployment.healthCheckWait, defaultHealthCheckWait)
	}
}

func TestWriteRepoConfigStoresRepoRelativePathsAndUpdatesGitignore(t *testing.T) {
	repoDir := newRepoDirForTest(t)
	cwd := filepath.Join(repoDir, "deploy")
	if err := os.MkdirAll(filepath.Join(repoDir, "build"), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte("bin/\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	opts := cliOptions{
		sshPort:       2200,
		sshPortSet:    true,
		remoteService: "api",
		deployment: deploymentOptions{
			logLines:           8,
			logLinesSet:        true,
			healthCheckWait:    7 * time.Second,
			healthCheckWaitSet: true,
		},
		args:       []string{"../build/api", "prod"},
		sshOptions: stringSliceFlag{"User=deploy"},
	}

	configPath := filepath.Join(repoDir, repoConfigFileName)
	if err := writeRepoConfig(configPath, repoDir, cwd, opts); err != nil {
		t.Fatalf("writeRepoConfig returned error: %v", err)
	}
	if err := ensureRepoGitignoreEntry(repoDir); err != nil {
		t.Fatalf("ensureRepoGitignoreEntry returned error: %v", err)
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	content := string(configData)
	if !strings.Contains(content, "local_path = \"build/api\"") {
		t.Fatalf("config missing repo-relative local path: %s", content)
	}
	if !strings.Contains(content, "remote_host = \"prod\"") {
		t.Fatalf("config missing remote_host: %s", content)
	}
	if !strings.Contains(content, "remote_service = \"api\"") {
		t.Fatalf("config missing remote_service: %s", content)
	}
	if !strings.Contains(content, "[deploy]") {
		t.Fatalf("config missing deploy section: %s", content)
	}
	if !strings.Contains(content, "log_lines = 8") {
		t.Fatalf("config missing log_lines: %s", content)
	}
	if !strings.Contains(content, "health_check_wait = \"7s\"") {
		t.Fatalf("config missing health_check_wait: %s", content)
	}
	if strings.Contains(content, "lock_timeout =") {
		t.Fatalf("config should not include deprecated lock_timeout: %s", content)
	}

	gitignoreData, err := os.ReadFile(filepath.Join(repoDir, ".gitignore"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(gitignoreData), repoConfigFileName) {
		t.Fatalf(".gitignore missing %s entry: %s", repoConfigFileName, string(gitignoreData))
	}

	loaded, err := loadRepoConfig(configPath, repoDir)
	if err != nil {
		t.Fatalf("loadRepoConfig returned error: %v", err)
	}
	if loaded.localPath != filepath.Join(repoDir, "build", "api") {
		t.Fatalf("loaded localPath = %q, want %q", loaded.localPath, filepath.Join(repoDir, "build", "api"))
	}
	if loaded.deployment.logLines != 8 {
		t.Fatalf("loaded logLines = %d, want %d", loaded.deployment.logLines, 8)
	}
	if loaded.deployment.healthCheckWait != 7*time.Second {
		t.Fatalf("loaded healthCheckWait = %v, want %v", loaded.deployment.healthCheckWait, 7*time.Second)
	}
}

func TestLoadRepoConfigRejectsRemovedDeployKeys(t *testing.T) {
	tests := []struct {
		name    string
		keyLine string
		want    string
	}{
		{name: "backup_dir", keyLine: "backup_dir = \"/var/tmp/custom-sdup\"", want: "unsupported key \"deploy.backup_dir\""},
		{name: "lock_timeout", keyLine: "lock_timeout = \"13m\"", want: "unsupported key \"deploy.lock_timeout\""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir := newRepoDirForTest(t)
			configPath := filepath.Join(repoDir, repoConfigFileName)
			if err := os.WriteFile(configPath, []byte(strings.Join([]string{
				"local_path = \"build/api\"",
				"remote_host = \"prod\"",
				"",
				"[deploy]",
				tt.keyLine,
			}, "\n")+"\n"), 0o600); err != nil {
				t.Fatalf("WriteFile returned error: %v", err)
			}

			_, err := loadRepoConfig(configPath, repoDir)
			if err == nil {
				t.Fatal("loadRepoConfig returned nil error for removed deploy key")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadRepoConfig error = %v, want %s", err, tt.want)
			}
		})
	}
}

func newRepoDirForTest(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	return repoDir
}

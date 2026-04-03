package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	sshconfig "github.com/kevinburke/ssh_config"
)

var defaultIdentityFileNames = []string{
	"id_rsa",
	"id_ecdsa",
	"id_ecdsa_sk",
	"id_ed25519",
	"id_ed25519_sk",
	"id_xmss",
	"id_dsa",
}

// HostConfig holds resolved SSH connection parameters.
type HostConfig struct {
	User           string
	Hostname       string
	Port           int
	IdentityFiles  []string
	IdentitiesOnly bool
	AgentSocket    string
}

type sshConfigReader interface {
	Get(string, string) (string, error)
	GetAll(string, string) ([]string, error)
}

func resolveSSHConfig(alias string, fallbackPort int) (*HostConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cfg := newHostConfig(alias, fallbackPort)
	if parsed, err := loadSSHConfig(homeDir); err == nil {
		applySSHConfigValues(cfg, parsed, alias, homeDir)
	}

	cfg.IdentityFiles = mergeIdentityFiles(cfg.IdentityFiles, defaultIdentityFiles(homeDir))
	if cfg.User == "" {
		cfg.User = os.Getenv("USER")
	}

	return cfg, nil
}

func newHostConfig(alias string, fallbackPort int) *HostConfig {
	return &HostConfig{
		User:          os.Getenv("USER"),
		Hostname:      alias,
		Port:          fallbackPort,
		IdentityFiles: []string{},
	}
}

func loadSSHConfig(homeDir string) (sshConfigReader, error) {
	f, err := os.Open(filepath.Join(homeDir, ".ssh", "config"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return sshconfig.Decode(bufio.NewReader(f))
}

func applySSHConfigValues(cfg *HostConfig, parsed sshConfigReader, alias, homeDir string) {
	if hostname, _ := parsed.Get(alias, "HostName"); hostname != "" {
		cfg.Hostname = hostname
	}
	if user, _ := parsed.Get(alias, "User"); user != "" {
		cfg.User = user
	}
	if port, _ := parsed.Get(alias, "Port"); port != "" {
		if parsedPort, err := parseInt(port); err == nil {
			cfg.Port = parsedPort
		}
	}
	if identities, _ := parsed.GetAll(alias, "IdentityFile"); len(identities) > 0 {
		cfg.IdentityFiles = append(cfg.IdentityFiles, expandIdentityFiles(identities, homeDir)...)
	}
	if identitiesOnly, _ := parsed.Get(alias, "IdentitiesOnly"); parseSSHBool(identitiesOnly) {
		cfg.IdentitiesOnly = true
	}
	if identityAgent, _ := parsed.Get(alias, "IdentityAgent"); strings.TrimSpace(identityAgent) != "" {
		applyIdentityAgent(cfg, identityAgent, homeDir)
	}
}

func expandIdentityFiles(files []string, homeDir string) []string {
	expanded := make([]string, 0, len(files))
	for _, file := range files {
		expanded = append(expanded, strings.Replace(file, "~", homeDir, 1))
	}
	return expanded
}

func applyIdentityAgent(cfg *HostConfig, identityAgent, homeDir string) {
	identityAgent = strings.TrimSpace(identityAgent)
	if strings.EqualFold(identityAgent, "none") {
		cfg.AgentSocket = "none"
		return
	}
	if strings.HasPrefix(identityAgent, "~") {
		cfg.AgentSocket = strings.Replace(identityAgent, "~", homeDir, 1)
		return
	}
	if identityAgent != "SSH_AUTH_SOCK" {
		cfg.AgentSocket = identityAgent
	}
}

func defaultIdentityFiles(homeDir string) []string {
	identityFiles := findDefaultIdentityFiles(homeDir)
	if len(identityFiles) > 0 {
		return identityFiles
	}
	return buildIdentityFilePaths(homeDir, defaultIdentityFileNames)
}

func buildIdentityFilePaths(homeDir string, names []string) []string {
	paths := make([]string, 0, len(names))
	for _, name := range names {
		paths = append(paths, filepath.Join(homeDir, ".ssh", name))
	}
	return paths
}

func findDefaultIdentityFiles(homeDir string) []string {
	sshDir := filepath.Join(homeDir, ".ssh")
	paths := make([]string, 0, len(defaultIdentityFileNames))
	for _, name := range defaultIdentityFileNames {
		path := filepath.Join(sshDir, name)
		if fileExists(path) {
			paths = append(paths, path)
		}
	}
	return paths
}

func parseSSHBool(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "yes" || v == "true" || v == "on" || v == "1"
}

func mergeIdentityFiles(primary []string, secondary []string) []string {
	out := make([]string, 0, len(primary)+len(secondary))
	seen := map[string]struct{}{}

	add := func(identityFile string) {
		identityFile = strings.TrimSpace(identityFile)
		if identityFile == "" || strings.EqualFold(identityFile, "none") {
			return
		}
		if _, ok := seen[identityFile]; ok {
			return
		}
		seen[identityFile] = struct{}{}
		out = append(out, identityFile)
	}

	for _, identityFile := range primary {
		add(identityFile)
	}
	for _, identityFile := range secondary {
		add(identityFile)
	}

	return out
}

package sshclient

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sshconfig "github.com/kevinburke/ssh_config"
)

const defaultPort = 22

var defaultIdentityFileNames = []string{
	"id_rsa",
	"id_ecdsa",
	"id_ecdsa_sk",
	"id_ed25519",
	"id_ed25519_sk",
	"id_xmss",
	"id_dsa",
}

type hostConfig struct {
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

func resolveConnectionConfig(remote string, options Options) (*hostConfig, error) {
	userOverride, hostAlias, portOverride := parseUserHostPort(remote)

	cfg, err := resolveSSHConfig(hostAlias, options.ConfigPath)
	if err != nil {
		return nil, err
	}

	if err := applyConnectionOverrides(cfg, userOverride, portOverride, options); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	return cfg, nil
}

func resolveSSHConfig(alias, configPath string) (*hostConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cfg := newHostConfig(alias)
	if parsed, err := loadSSHConfig(homeDir, configPath); err == nil {
		applySSHConfigValues(cfg, parsed, alias, homeDir)
	} else if strings.TrimSpace(configPath) != "" {
		return nil, err
	}

	cfg.IdentityFiles = mergeIdentityFiles(cfg.IdentityFiles, defaultIdentityFiles(homeDir))
	if cfg.User == "" {
		cfg.User = os.Getenv("USER")
	}

	return cfg, nil
}

func newHostConfig(alias string) *hostConfig {
	return &hostConfig{
		User:          os.Getenv("USER"),
		Hostname:      alias,
		IdentityFiles: []string{},
	}
}

func loadSSHConfig(homeDir, configPath string) (sshConfigReader, error) {
	if strings.TrimSpace(configPath) == "" {
		configPath = filepath.Join(homeDir, ".ssh", "config")
	} else {
		configPath = expandHomePath(configPath, homeDir)
	}

	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return sshconfig.Decode(bufio.NewReader(f))
}

func applySSHConfigValues(cfg *hostConfig, parsed sshConfigReader, alias, homeDir string) {
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
		expanded = append(expanded, expandHomePath(file, homeDir))
	}
	return expanded
}

func applyIdentityAgent(cfg *hostConfig, identityAgent, homeDir string) {
	identityAgent = strings.TrimSpace(identityAgent)
	if strings.EqualFold(identityAgent, "none") {
		cfg.AgentSocket = "none"
		return
	}
	if strings.HasPrefix(identityAgent, "~") {
		cfg.AgentSocket = expandHomePath(identityAgent, homeDir)
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

func applyConnectionOverrides(cfg *hostConfig, userOverride string, portOverride int, options Options) error {
	if userOverride != "" {
		cfg.User = userOverride
	}
	if portOverride > 0 {
		cfg.Port = portOverride
	}

	if err := applyOptions(cfg, options); err != nil {
		return err
	}
	return nil
}

func applyOptions(cfg *hostConfig, options Options) error {
	if err := applyRawOptions(cfg, options.RawOptions); err != nil {
		return err
	}
	if err := applyIdentityFileOverrides(cfg, options.IdentityFiles); err != nil {
		return err
	}
	if options.Port != nil {
		cfg.Port = *options.Port
	}
	return nil
}

func applyRawOptions(cfg *hostConfig, rawOptions []string) error {
	if len(rawOptions) == 0 {
		return nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	for _, raw := range rawOptions {
		key, value, err := parseSSHOption(raw)
		if err != nil {
			return err
		}

		switch strings.ToLower(key) {
		case "hostname":
			cfg.Hostname = strings.TrimSpace(value)
		case "user":
			cfg.User = strings.TrimSpace(value)
		case "port":
			port, err := parseInt(value)
			if err != nil {
				return fmt.Errorf("invalid -o Port value %q: %w", value, err)
			}
			cfg.Port = port
		case "identityfile":
			cfg.IdentityFiles = mergeIdentityFiles([]string{expandHomePath(value, homeDir)}, cfg.IdentityFiles)
		case "identitiesonly":
			cfg.IdentitiesOnly = parseSSHBool(value)
		case "identityagent":
			applyIdentityAgent(cfg, value, homeDir)
		default:
			return fmt.Errorf("unsupported -o option: %s", key)
		}
	}

	return nil
}

func parseSSHOption(spec string) (string, string, error) {
	parts := strings.SplitN(spec, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("-o expects KEY=VALUE, got %q", spec)
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" {
		return "", "", fmt.Errorf("-o expects KEY=VALUE, got %q", spec)
	}

	return key, value, nil
}

func applyIdentityFileOverrides(cfg *hostConfig, identityFiles []string) error {
	if len(identityFiles) == 0 {
		return nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	expanded := make([]string, 0, len(identityFiles))
	for _, identityFile := range identityFiles {
		expanded = append(expanded, expandHomePath(identityFile, homeDir))
	}
	cfg.IdentityFiles = mergeIdentityFiles(expanded, cfg.IdentityFiles)
	return nil
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

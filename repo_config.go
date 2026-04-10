package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/zjyl1994/sdup/pkg/sshclient"
)

const repoConfigFileName = ".sdup.toml"

type repoContext struct {
	rootDir    string
	configPath string
}

type repoConfig struct {
	localPath     string
	remoteHost    string
	remoteService string
	ssh           sshOverride
	deployment    deploymentOverride
}

type repoConfigDocument struct {
	LocalPath     string              `toml:"local_path"`
	RemoteHost    string              `toml:"remote_host"`
	RemoteService string              `toml:"remote_service"`
	SSH           *repoSSHDocument    `toml:"ssh,omitempty"`
	Deploy        *repoDeployDocument `toml:"deploy,omitempty"`
}

type repoSSHDocument struct {
	Config           *string  `toml:"config,omitempty"`
	Port             *int     `toml:"port,omitempty"`
	IgnoreKnownHosts *bool    `toml:"ignore_known_hosts,omitempty"`
	IdentityFiles    []string `toml:"identity_files,omitempty"`
	Options          []string `toml:"options,omitempty"`
}

type repoDeployDocument struct {
	LogLines        *int    `toml:"log_lines,omitempty"`
	HealthCheckWait *string `toml:"health_check_wait,omitempty"`
}

func resolveInvocationOptions(cli cliInput, cwd string) (resolvedInvocation, repoContext, error) {
	repoCtx, err := resolveRepoContext(cwd)
	if err != nil {
		return resolvedInvocation{}, repoContext{}, err
	}

	cfg, err := loadRepoConfig(repoCtx.configPath, repoCtx.rootDir)
	if err != nil {
		return resolvedInvocation{}, repoCtx, err
	}

	inv := resolveInvocation(cfg, cli)
	if err := validateResolvedInvocation(inv); err != nil {
		return resolvedInvocation{}, repoCtx, err
	}

	return inv, repoCtx, nil
}

func resolveRepoContext(cwd string) (repoContext, error) {
	absCWD, err := filepath.Abs(cwd)
	if err != nil {
		return repoContext{}, err
	}

	rootDir := findRepoRoot(absCWD)
	return repoContext{
		rootDir:    rootDir,
		configPath: filepath.Join(rootDir, repoConfigFileName),
	}, nil
}

func findRepoRoot(startDir string) string {
	dir := startDir
	for {
		if pathExists(filepath.Join(dir, ".git")) {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return startDir
		}
		dir = parent
	}
}

func loadRepoConfig(configPath, baseDir string) (repoConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return repoConfig{}, nil
		}
		return repoConfig{}, err
	}
	return parseRepoConfig(string(data), baseDir)
}

func parseRepoConfig(content, baseDir string) (repoConfig, error) {
	var doc repoConfigDocument
	meta, err := toml.Decode(content, &doc)
	if err != nil {
		return repoConfig{}, fmt.Errorf("%s: %w", repoConfigFileName, err)
	}
	if err := validateRepoConfigKeys(meta); err != nil {
		return repoConfig{}, fmt.Errorf("%s: %w", repoConfigFileName, err)
	}
	return repoConfigFromDocument(doc, baseDir)
}

func validateRepoConfigKeys(meta toml.MetaData) error {
	undecoded := meta.Undecoded()
	if len(undecoded) == 0 {
		return nil
	}
	return fmt.Errorf("unsupported key %q", undecoded[0].String())
}

func repoConfigFromDocument(doc repoConfigDocument, baseDir string) (repoConfig, error) {
	var cfg repoConfig

	if strings.TrimSpace(doc.LocalPath) != "" {
		resolved, err := resolvePathValue(doc.LocalPath, baseDir)
		if err != nil {
			return repoConfig{}, err
		}
		cfg.localPath = resolved
	}
	cfg.remoteHost = doc.RemoteHost
	cfg.remoteService = doc.RemoteService

	if doc.SSH != nil {
		sshCfg, err := repoSSHOverrideFromDocument(*doc.SSH, baseDir)
		if err != nil {
			return repoConfig{}, err
		}
		cfg.ssh = sshCfg
	}

	if doc.Deploy != nil {
		deployCfg, err := repoDeploymentOverrideFromDocument(*doc.Deploy)
		if err != nil {
			return repoConfig{}, err
		}
		cfg.deployment = deployCfg
	}

	return cfg, nil
}

func repoSSHOverrideFromDocument(doc repoSSHDocument, baseDir string) (sshOverride, error) {
	var cfg sshOverride

	if doc.Config != nil {
		resolved, err := resolvePathValue(*doc.Config, baseDir)
		if err != nil {
			return sshOverride{}, err
		}
		cfg.configPath = stringPtr(resolved)
	}
	if doc.Port != nil {
		if err := sshclient.ValidatePort(*doc.Port); err != nil {
			return sshOverride{}, err
		}
		cfg.port = intPtr(*doc.Port)
	}
	if doc.IgnoreKnownHosts != nil {
		cfg.ignoreKnownHosts = boolPtr(*doc.IgnoreKnownHosts)
	}
	if len(doc.IdentityFiles) > 0 {
		cfg.identityFiles = make([]string, 0, len(doc.IdentityFiles))
		for _, identityFile := range doc.IdentityFiles {
			resolved, err := resolvePathValue(identityFile, baseDir)
			if err != nil {
				return sshOverride{}, err
			}
			cfg.identityFiles = append(cfg.identityFiles, resolved)
		}
	}
	if len(doc.Options) > 0 {
		cfg.rawOptions = cloneStrings(doc.Options)
	}

	return cfg, nil
}

func repoDeploymentOverrideFromDocument(doc repoDeployDocument) (deploymentOverride, error) {
	var cfg deploymentOverride

	if doc.LogLines != nil {
		if *doc.LogLines < 0 {
			return deploymentOverride{}, fmt.Errorf("log_lines must be >= 0")
		}
		cfg.logLines = intPtr(*doc.LogLines)
	}
	if doc.HealthCheckWait != nil {
		duration, err := time.ParseDuration(*doc.HealthCheckWait)
		if err != nil {
			return deploymentOverride{}, fmt.Errorf("expected duration string, got %q", *doc.HealthCheckWait)
		}
		if duration < 0 {
			return deploymentOverride{}, fmt.Errorf("health_check_wait must be >= 0")
		}
		cfg.healthCheckWait = durationPtr(duration)
	}

	return cfg, nil
}

func resolvePathValue(value, baseDir string) (string, error) {
	value, err := expandHomePath(value)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	return filepath.Clean(filepath.Join(baseDir, value)), nil
}

func writeRepoConfig(configPath, rootDir, cwd string, inv resolvedInvocation) error {
	cfg, err := repoConfigForWrite(rootDir, cwd, inv.effectiveConfig)
	if err != nil {
		return err
	}
	data, err := encodeRepoConfig(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0o600)
}

func repoConfigForWrite(rootDir, cwd string, cfg repoConfig) (repoConfig, error) {
	written := repoConfig{
		remoteHost:    cfg.remoteHost,
		remoteService: cfg.remoteService,
		ssh: sshOverride{
			port:             cloneIntPointer(cfg.ssh.port),
			ignoreKnownHosts: cloneBoolPointer(cfg.ssh.ignoreKnownHosts),
			rawOptions:       cloneStrings(cfg.ssh.rawOptions),
		},
		deployment: deploymentOverride{
			logLines:        cloneIntPointer(cfg.deployment.logLines),
			healthCheckWait: cloneDurationPointer(cfg.deployment.healthCheckWait),
		},
	}

	if cfg.localPath != "" {
		localPath, err := pathForRepoConfig(cfg.localPath, rootDir, cwd)
		if err != nil {
			return repoConfig{}, err
		}
		written.localPath = localPath
	}
	if cfg.ssh.configPath != nil {
		configPath, err := pathForRepoConfig(*cfg.ssh.configPath, rootDir, cwd)
		if err != nil {
			return repoConfig{}, err
		}
		written.ssh.configPath = stringPtr(configPath)
	}
	if len(cfg.ssh.identityFiles) > 0 {
		written.ssh.identityFiles = make([]string, 0, len(cfg.ssh.identityFiles))
		for _, identityFile := range cfg.ssh.identityFiles {
			configPath, err := pathForRepoConfig(identityFile, rootDir, cwd)
			if err != nil {
				return repoConfig{}, err
			}
			written.ssh.identityFiles = append(written.ssh.identityFiles, configPath)
		}
	}

	return written, nil
}

func pathForRepoConfig(value, rootDir, cwd string) (string, error) {
	resolved, err := resolvePathValue(value, cwd)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(rootDir, resolved)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel), nil
	}

	return resolved, nil
}

func encodeRepoConfig(cfg repoConfig) ([]byte, error) {
	doc := repoConfigDocument{
		LocalPath:     cfg.localPath,
		RemoteHost:    cfg.remoteHost,
		RemoteService: cfg.remoteService,
	}

	if sshDoc := buildRepoSSHDocument(cfg.ssh); sshDoc != nil {
		doc.SSH = sshDoc
	}
	if deployDoc := buildRepoDeployDocument(cfg.deployment); deployDoc != nil {
		doc.Deploy = deployDoc
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildRepoSSHDocument(cfg sshOverride) *repoSSHDocument {
	doc := &repoSSHDocument{}
	hasValues := false

	if cfg.configPath != nil {
		value := *cfg.configPath
		doc.Config = &value
		hasValues = true
	}
	if cfg.port != nil {
		value := *cfg.port
		doc.Port = &value
		hasValues = true
	}
	if cfg.ignoreKnownHosts != nil {
		value := *cfg.ignoreKnownHosts
		doc.IgnoreKnownHosts = &value
		hasValues = true
	}
	if len(cfg.identityFiles) > 0 {
		doc.IdentityFiles = cloneStrings(cfg.identityFiles)
		hasValues = true
	}
	if len(cfg.rawOptions) > 0 {
		doc.Options = cloneStrings(cfg.rawOptions)
		hasValues = true
	}

	if !hasValues {
		return nil
	}
	return doc
}

func buildRepoDeployDocument(cfg deploymentOverride) *repoDeployDocument {
	doc := &repoDeployDocument{}
	hasValues := false

	if cfg.logLines != nil {
		value := *cfg.logLines
		doc.LogLines = &value
		hasValues = true
	}
	if cfg.healthCheckWait != nil {
		value := cfg.healthCheckWait.String()
		doc.HealthCheckWait = &value
		hasValues = true
	}

	if !hasValues {
		return nil
	}
	return doc
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	return intPtr(*value)
}

func cloneBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	return boolPtr(*value)
}

func cloneDurationPointer(value *time.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	return durationPtr(*value)
}

func ensureRepoGitignoreEntry(rootDir string) error {
	gitignorePath := filepath.Join(rootDir, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(gitignorePath, []byte(repoConfigFileName+"\n"), 0o644)
		}
		return err
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == repoConfigFileName {
			return nil
		}
	}

	content := string(data)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += repoConfigFileName + "\n"
	return os.WriteFile(gitignorePath, []byte(content), 0o644)
}

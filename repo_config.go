package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const repoConfigFileName = ".sdup.toml"

type repoContext struct {
	rootDir    string
	configPath string
}

type repoConfig struct {
	localPath        string
	remoteHost       string
	remoteService    string
	deployment       deploymentOptions
	sshPort          int
	sshPortSet       bool
	sshConfigPath    string
	sshConfigSet     bool
	identityFiles    []string
	sshOptions       []string
	ignoreKnownHosts bool
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
	BackupDir       *string `toml:"backup_dir,omitempty"`
	LogLines        *int    `toml:"log_lines,omitempty"`
	HealthCheckWait *string `toml:"health_check_wait,omitempty"`
	LockTimeout     *string `toml:"lock_timeout,omitempty"`
}

func resolveInvocationOptions(cli cliOptions, cwd string) (cliOptions, repoContext, error) {
	repoCtx, err := resolveRepoContext(cwd)
	if err != nil {
		return cliOptions{}, repoContext{}, err
	}

	cfg, err := loadRepoConfig(repoCtx.configPath, repoCtx.rootDir)
	if err != nil {
		return cliOptions{}, repoCtx, err
	}

	opts := mergeCLIOptions(cfg, cli)
	if opts.remoteService == "" && len(opts.args) > 0 && strings.TrimSpace(opts.args[0]) != "" {
		opts.remoteService = filepath.Base(opts.args[0])
	}
	if err := validateInvocationOptions(opts); err != nil {
		return cliOptions{}, repoCtx, err
	}

	return opts, repoCtx, nil
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

func validateInvocationOptions(opts cliOptions) error {
	missing := []string{}
	if len(opts.args) < 1 || strings.TrimSpace(opts.args[0]) == "" {
		missing = append(missing, "local_path")
	}
	if len(opts.args) < 2 || strings.TrimSpace(opts.args[1]) == "" {
		missing = append(missing, "remote_host")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required arguments: %s", strings.Join(missing, ", "))
	}
	return nil
}

func mergeCLIOptions(cfg repoConfig, cli cliOptions) cliOptions {
	localPath := cfg.localPath
	remoteHost := cfg.remoteHost
	if len(cli.args) >= 1 {
		localPath = cli.args[0]
	}
	if len(cli.args) >= 2 {
		remoteHost = cli.args[1]
	}

	merged := cliOptions{
		sshPort:          cfg.sshPort,
		sshPortSet:       cfg.sshPortSet,
		sshConfigPath:    cfg.sshConfigPath,
		sshConfigSet:     cfg.sshConfigSet,
		identityFiles:    append(stringSliceFlag(nil), cfg.identityFiles...),
		sshOptions:       append(stringSliceFlag(nil), cfg.sshOptions...),
		ignoreKnownHosts: cfg.ignoreKnownHosts,
		remoteService:    cfg.remoteService,
		deployment:       cfg.deployment,
		writeConfig:      cli.writeConfig,
	}

	if localPath != "" || remoteHost != "" {
		merged.args = append(merged.args, localPath)
	}
	if remoteHost != "" {
		if len(merged.args) == 0 {
			merged.args = append(merged.args, "")
		}
		merged.args = append(merged.args, remoteHost)
	}

	if cli.remoteService != "" {
		merged.remoteService = cli.remoteService
	}
	if cli.sshConfigSet {
		merged.sshConfigPath = cli.sshConfigPath
		merged.sshConfigSet = true
	}
	if cli.sshPortSet {
		merged.sshPort = cli.sshPort
		merged.sshPortSet = true
	}
	if len(cli.identityFiles) > 0 {
		merged.identityFiles = append(append(stringSliceFlag(nil), cli.identityFiles...), cfg.identityFiles...)
	}
	if len(cli.sshOptions) > 0 {
		merged.sshOptions = append(append(stringSliceFlag(nil), cfg.sshOptions...), cli.sshOptions...)
	}
	if cli.ignoreKnownHosts {
		merged.ignoreKnownHosts = true
	}

	merged.deployment = buildDeploymentOptions(merged)
	return merged
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
		if doc.SSH.Config != nil {
			resolved, err := resolvePathValue(*doc.SSH.Config, baseDir)
			if err != nil {
				return repoConfig{}, err
			}
			cfg.sshConfigPath = resolved
			cfg.sshConfigSet = true
		}
		if doc.SSH.Port != nil {
			cfg.sshPort = *doc.SSH.Port
			cfg.sshPortSet = true
		}
		if doc.SSH.IgnoreKnownHosts != nil {
			cfg.ignoreKnownHosts = *doc.SSH.IgnoreKnownHosts
		}
		if len(doc.SSH.IdentityFiles) > 0 {
			cfg.identityFiles = make([]string, 0, len(doc.SSH.IdentityFiles))
			for _, identityFile := range doc.SSH.IdentityFiles {
				resolved, err := resolvePathValue(identityFile, baseDir)
				if err != nil {
					return repoConfig{}, err
				}
				cfg.identityFiles = append(cfg.identityFiles, resolved)
			}
		}
		if len(doc.SSH.Options) > 0 {
			cfg.sshOptions = append([]string(nil), doc.SSH.Options...)
		}
	}

	if doc.Deploy != nil {
		if doc.Deploy.BackupDir != nil {
			if strings.TrimSpace(*doc.Deploy.BackupDir) == "" {
				return repoConfig{}, fmt.Errorf("backup_dir must not be empty")
			}
			cfg.deployment.backupDir = *doc.Deploy.BackupDir
			cfg.deployment.backupDirSet = true
		}
		if doc.Deploy.LogLines != nil {
			if *doc.Deploy.LogLines < 0 {
				return repoConfig{}, fmt.Errorf("log_lines must be >= 0")
			}
			cfg.deployment.logLines = *doc.Deploy.LogLines
			cfg.deployment.logLinesSet = true
		}
		if doc.Deploy.HealthCheckWait != nil {
			duration, err := time.ParseDuration(*doc.Deploy.HealthCheckWait)
			if err != nil {
				return repoConfig{}, fmt.Errorf("expected duration string, got %q", *doc.Deploy.HealthCheckWait)
			}
			if duration < 0 {
				return repoConfig{}, fmt.Errorf("health_check_wait must be >= 0")
			}
			cfg.deployment.healthCheckWait = duration
			cfg.deployment.healthCheckWaitSet = true
		}
		if doc.Deploy.LockTimeout != nil {
			duration, err := time.ParseDuration(*doc.Deploy.LockTimeout)
			if err != nil {
				return repoConfig{}, fmt.Errorf("expected duration string, got %q", *doc.Deploy.LockTimeout)
			}
			if duration < 0 {
				return repoConfig{}, fmt.Errorf("lock_timeout must be >= 0")
			}
			cfg.deployment.lockTimeout = duration
			cfg.deployment.lockTimeoutSet = true
		}
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

func writeRepoConfig(configPath, rootDir, cwd string, opts cliOptions) error {
	cfg, err := repoConfigFromOptions(rootDir, cwd, opts)
	if err != nil {
		return err
	}
	data, err := encodeRepoConfig(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0o600)
}

func repoConfigFromOptions(rootDir, cwd string, opts cliOptions) (repoConfig, error) {
	localPath := ""
	remoteHost := ""
	if len(opts.args) > 0 {
		var err error
		localPath, err = pathForRepoConfig(opts.args[0], rootDir, cwd)
		if err != nil {
			return repoConfig{}, err
		}
	}
	if len(opts.args) > 1 {
		remoteHost = opts.args[1]
	}

	cfg := repoConfig{
		localPath:        localPath,
		remoteHost:       remoteHost,
		remoteService:    opts.remoteService,
		deployment:       opts.deployment,
		sshPort:          opts.sshPort,
		sshPortSet:       opts.sshPortSet,
		ignoreKnownHosts: opts.ignoreKnownHosts,
	}

	if opts.sshConfigSet {
		cfg.sshConfigSet = true
		cfgPath, err := pathForRepoConfig(opts.sshConfigPath, rootDir, cwd)
		if err != nil {
			return repoConfig{}, err
		}
		cfg.sshConfigPath = cfgPath
	}

	if len(opts.identityFiles) > 0 {
		cfg.identityFiles = make([]string, 0, len(opts.identityFiles))
		for _, identityFile := range opts.identityFiles {
			configPath, err := pathForRepoConfig(identityFile, rootDir, cwd)
			if err != nil {
				return repoConfig{}, err
			}
			cfg.identityFiles = append(cfg.identityFiles, configPath)
		}
	}
	if len(opts.sshOptions) > 0 {
		cfg.sshOptions = append([]string(nil), opts.sshOptions...)
	}

	return cfg, nil
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

	if sshDoc := buildRepoSSHDocument(cfg); sshDoc != nil {
		doc.SSH = sshDoc
	}
	if deployDoc := buildRepoDeployDocument(cfg); deployDoc != nil {
		doc.Deploy = deployDoc
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildRepoSSHDocument(cfg repoConfig) *repoSSHDocument {
	doc := &repoSSHDocument{}
	hasValues := false

	if cfg.sshConfigSet {
		value := cfg.sshConfigPath
		doc.Config = &value
		hasValues = true
	}
	if cfg.sshPortSet {
		value := cfg.sshPort
		doc.Port = &value
		hasValues = true
	}
	if cfg.ignoreKnownHosts {
		value := true
		doc.IgnoreKnownHosts = &value
		hasValues = true
	}
	if len(cfg.identityFiles) > 0 {
		doc.IdentityFiles = append([]string(nil), cfg.identityFiles...)
		hasValues = true
	}
	if len(cfg.sshOptions) > 0 {
		doc.Options = append([]string(nil), cfg.sshOptions...)
		hasValues = true
	}

	if !hasValues {
		return nil
	}
	return doc
}

func buildRepoDeployDocument(cfg repoConfig) *repoDeployDocument {
	doc := &repoDeployDocument{}
	hasValues := false

	if cfg.deployment.backupDirSet {
		value := cfg.deployment.backupDir
		doc.BackupDir = &value
		hasValues = true
	}
	if cfg.deployment.logLinesSet {
		value := cfg.deployment.logLines
		doc.LogLines = &value
		hasValues = true
	}
	if cfg.deployment.healthCheckWaitSet {
		value := cfg.deployment.healthCheckWait.String()
		doc.HealthCheckWait = &value
		hasValues = true
	}
	if cfg.deployment.lockTimeoutSet {
		value := cfg.deployment.lockTimeout.String()
		doc.LockTimeout = &value
		hasValues = true
	}

	if !hasValues {
		return nil
	}
	return doc
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

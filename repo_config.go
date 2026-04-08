package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	sshPort          int
	sshPortSet       bool
	sshConfigPath    string
	sshConfigSet     bool
	identityFiles    []string
	sshOptions       []string
	ignoreKnownHosts bool
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
	var cfg repoConfig
	section := ""

	for lineNumber, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(stripTOMLComment(rawLine))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return repoConfig{}, fmt.Errorf("%s:%d: invalid section header", repoConfigFileName, lineNumber+1)
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section != "ssh" {
				return repoConfig{}, fmt.Errorf("%s:%d: unsupported section %q", repoConfigFileName, lineNumber+1, section)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return repoConfig{}, fmt.Errorf("%s:%d: expected key = value", repoConfigFileName, lineNumber+1)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if err := applyRepoConfigValue(&cfg, section, key, value, baseDir); err != nil {
			return repoConfig{}, fmt.Errorf("%s:%d: %w", repoConfigFileName, lineNumber+1, err)
		}
	}

	return cfg, nil
}

func applyRepoConfigValue(cfg *repoConfig, section, key, value, baseDir string) error {
	switch section {
	case "":
		switch key {
		case "local_path":
			resolved, err := resolveConfigPath(value, baseDir)
			if err != nil {
				return err
			}
			cfg.localPath = resolved
		case "remote_host":
			parsed, err := parseTOMLString(value)
			if err != nil {
				return err
			}
			cfg.remoteHost = parsed
		case "remote_service":
			parsed, err := parseTOMLString(value)
			if err != nil {
				return err
			}
			cfg.remoteService = parsed
		default:
			return fmt.Errorf("unsupported key %q", key)
		}
	case "ssh":
		switch key {
		case "config":
			resolved, err := resolveConfigPath(value, baseDir)
			if err != nil {
				return err
			}
			cfg.sshConfigPath = resolved
			cfg.sshConfigSet = true
		case "port":
			parsed, err := parseTOMLInt(value)
			if err != nil {
				return err
			}
			cfg.sshPort = parsed
			cfg.sshPortSet = true
		case "ignore_known_hosts":
			parsed, err := parseTOMLBool(value)
			if err != nil {
				return err
			}
			cfg.ignoreKnownHosts = parsed
		case "identity_files":
			parsed, err := parseTOMLStringArray(value)
			if err != nil {
				return err
			}
			cfg.identityFiles = make([]string, 0, len(parsed))
			for _, item := range parsed {
				resolved, err := resolvePathValue(item, baseDir)
				if err != nil {
					return err
				}
				cfg.identityFiles = append(cfg.identityFiles, resolved)
			}
		case "options":
			parsed, err := parseTOMLStringArray(value)
			if err != nil {
				return err
			}
			cfg.sshOptions = append([]string(nil), parsed...)
		default:
			return fmt.Errorf("unsupported key %q", key)
		}
	default:
		return fmt.Errorf("unsupported section %q", section)
	}

	return nil
}

func resolveConfigPath(value, baseDir string) (string, error) {
	parsed, err := parseTOMLString(value)
	if err != nil {
		return "", err
	}
	return resolvePathValue(parsed, baseDir)
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

func stripTOMLComment(line string) string {
	inString := false
	escaped := false
	for i := 0; i < len(line); i++ {
		switch {
		case escaped:
			escaped = false
		case line[i] == '\\' && inString:
			escaped = true
		case line[i] == '"':
			inString = !inString
		case line[i] == '#' && !inString:
			return line[:i]
		}
	}
	return line
}

func parseTOMLString(value string) (string, error) {
	parsed, err := strconv.Unquote(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("expected quoted string, got %q", value)
	}
	return parsed, nil
}

func parseTOMLInt(value string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("expected integer, got %q", value)
	}
	return parsed, nil
}

func parseTOMLBool(value string) (bool, error) {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean, got %q", value)
	}
}

func parseTOMLStringArray(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, fmt.Errorf("expected string array, got %q", value)
	}

	body := strings.TrimSpace(value[1 : len(value)-1])
	if body == "" {
		return nil, nil
	}

	parts := []string{}
	start := 0
	inString := false
	escaped := false
	for i := 0; i < len(body); i++ {
		switch {
		case escaped:
			escaped = false
		case body[i] == '\\' && inString:
			escaped = true
		case body[i] == '"':
			inString = !inString
		case body[i] == ',' && !inString:
			parts = append(parts, strings.TrimSpace(body[start:i]))
			start = i + 1
		}
	}
	if inString {
		return nil, fmt.Errorf("unterminated string array")
	}
	parts = append(parts, strings.TrimSpace(body[start:]))

	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("expected string array, got %q", value)
		}
		item, err := parseTOMLString(part)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func writeRepoConfig(configPath, rootDir, cwd string, opts cliOptions) error {
	cfg, err := repoConfigFromOptions(rootDir, cwd, opts)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, []byte(renderRepoConfig(cfg)), 0o600)
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

func renderRepoConfig(cfg repoConfig) string {
	lines := []string{
		fmt.Sprintf("local_path = %s", strconv.Quote(cfg.localPath)),
		fmt.Sprintf("remote_host = %s", strconv.Quote(cfg.remoteHost)),
		fmt.Sprintf("remote_service = %s", strconv.Quote(cfg.remoteService)),
	}

	sshLines := []string{}
	if cfg.sshConfigSet {
		sshLines = append(sshLines, fmt.Sprintf("config = %s", strconv.Quote(cfg.sshConfigPath)))
	}
	if cfg.sshPortSet {
		sshLines = append(sshLines, fmt.Sprintf("port = %d", cfg.sshPort))
	}
	if cfg.ignoreKnownHosts {
		sshLines = append(sshLines, "ignore_known_hosts = true")
	}
	if len(cfg.identityFiles) > 0 {
		sshLines = append(sshLines, fmt.Sprintf("identity_files = %s", renderTOMLStringArray(cfg.identityFiles)))
	}
	if len(cfg.sshOptions) > 0 {
		sshLines = append(sshLines, fmt.Sprintf("options = %s", renderTOMLStringArray(cfg.sshOptions)))
	}

	if len(sshLines) > 0 {
		lines = append(lines, "", "[ssh]")
		lines = append(lines, sshLines...)
	}

	return strings.Join(lines, "\n") + "\n"
}

func renderTOMLStringArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, strconv.Quote(value))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
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

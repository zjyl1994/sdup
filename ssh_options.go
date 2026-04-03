package main

import (
	"fmt"
	"os"
	"strings"
)

type sshCLIOptions struct {
	Port          *int
	ConfigPath    string
	ConfigPathSet bool
	IdentityFiles []string
	RawOptions    []string
}

func buildSSHCLIOptions(opts cliOptions) sshCLIOptions {
	sshOptions := sshCLIOptions{
		ConfigPath:    opts.sshConfigPath,
		ConfigPathSet: opts.sshConfigSet,
		IdentityFiles: append([]string(nil), opts.identityFiles...),
		RawOptions:    append([]string(nil), opts.sshOptions...),
	}
	if opts.sshPortSet {
		sshOptions.Port = &opts.sshPort
	}
	return sshOptions
}

func applySSHCLIOptions(cfg *HostConfig, options sshCLIOptions) error {
	if err := applyRawSSHOptions(cfg, options.RawOptions); err != nil {
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

func applyRawSSHOptions(cfg *HostConfig, rawOptions []string) error {
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

func applyIdentityFileOverrides(cfg *HostConfig, identityFiles []string) error {
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

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type cliInput struct {
	localPath     string
	remoteHost    string
	remoteService string
	writeConfig   bool
	ssh           sshOverride
	deployment    deploymentOverride
}

type resolvedInvocation struct {
	localPath       string
	remoteHost      string
	remoteService   string
	writeConfig     bool
	ssh             resolvedSSHOptions
	deployment      deploymentOptions
	effectiveConfig repoConfig
}

type sshOverride struct {
	port             *int
	configPath       *string
	identityFiles    []string
	rawOptions       []string
	ignoreKnownHosts *bool
}

type resolvedSSHOptions struct {
	port             *int
	configPath       string
	identityFiles    []string
	rawOptions       []string
	ignoreKnownHosts bool
}

type deploymentOverride struct {
	logLines        *int
	healthCheckWait *time.Duration
}

func resolveInvocation(cfg repoConfig, cli cliInput) resolvedInvocation {
	localPath := firstNonEmpty(cli.localPath, cfg.localPath)
	remoteHost := firstNonEmpty(cli.remoteHost, cfg.remoteHost)
	remoteService := firstNonEmpty(cli.remoteService, cfg.remoteService)
	if remoteService == "" && localPath != "" {
		remoteService = filepath.Base(localPath)
	}

	effectiveSSH := mergeSSHOverride(cfg.ssh, cli.ssh)
	effectiveDeployment := mergeDeploymentOverride(cfg.deployment, cli.deployment)

	return resolvedInvocation{
		localPath:     localPath,
		remoteHost:    remoteHost,
		remoteService: remoteService,
		writeConfig:   cli.writeConfig,
		ssh:           resolveSSHOptions(effectiveSSH),
		deployment:    resolveDeploymentOptions(effectiveDeployment),
		effectiveConfig: repoConfig{
			localPath:     localPath,
			remoteHost:    remoteHost,
			remoteService: remoteService,
			ssh:           effectiveSSH,
			deployment:    effectiveDeployment,
		},
	}
}

func resolveSSHOptions(override sshOverride) resolvedSSHOptions {
	resolved := resolvedSSHOptions{
		identityFiles: cloneStrings(override.identityFiles),
		rawOptions:    cloneStrings(override.rawOptions),
	}
	if override.port != nil {
		resolved.port = intPtr(*override.port)
	}
	if override.configPath != nil {
		resolved.configPath = *override.configPath
	}
	if override.ignoreKnownHosts != nil {
		resolved.ignoreKnownHosts = *override.ignoreKnownHosts
	}
	return resolved
}

func resolveDeploymentOptions(override deploymentOverride) deploymentOptions {
	resolved := defaultDeploymentOptions()
	if override.logLines != nil {
		resolved.logLines = *override.logLines
	}
	if override.healthCheckWait != nil {
		resolved.healthCheckWait = *override.healthCheckWait
	}
	return resolved
}

func mergeSSHOverride(base, override sshOverride) sshOverride {
	merged := sshOverride{
		identityFiles: cloneStrings(base.identityFiles),
		rawOptions:    cloneStrings(base.rawOptions),
	}
	if base.port != nil {
		merged.port = intPtr(*base.port)
	}
	if base.configPath != nil {
		merged.configPath = stringPtr(*base.configPath)
	}
	if base.ignoreKnownHosts != nil {
		merged.ignoreKnownHosts = boolPtr(*base.ignoreKnownHosts)
	}

	if override.port != nil {
		merged.port = intPtr(*override.port)
	}
	if override.configPath != nil {
		merged.configPath = stringPtr(*override.configPath)
	}
	if len(override.identityFiles) > 0 {
		merged.identityFiles = append(cloneStrings(override.identityFiles), merged.identityFiles...)
	}
	if len(override.rawOptions) > 0 {
		merged.rawOptions = append(merged.rawOptions, override.rawOptions...)
	}
	if override.ignoreKnownHosts != nil {
		merged.ignoreKnownHosts = boolPtr(*override.ignoreKnownHosts)
	}

	return merged
}

func mergeDeploymentOverride(base, override deploymentOverride) deploymentOverride {
	merged := deploymentOverride{}
	if base.logLines != nil {
		merged.logLines = intPtr(*base.logLines)
	}
	if base.healthCheckWait != nil {
		merged.healthCheckWait = durationPtr(*base.healthCheckWait)
	}
	if override.logLines != nil {
		merged.logLines = intPtr(*override.logLines)
	}
	if override.healthCheckWait != nil {
		merged.healthCheckWait = durationPtr(*override.healthCheckWait)
	}
	return merged
}

func validateResolvedInvocation(inv resolvedInvocation) error {
	missing := []string{}
	if inv.localPath == "" {
		missing = append(missing, "local_path")
	}
	if inv.remoteHost == "" {
		missing = append(missing, "remote_host")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required arguments: %s", strings.Join(missing, ", "))
	}
	return nil
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func intPtr(value int) *int {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

func stringPtr(value string) *string {
	return &value
}

func durationPtr(value time.Duration) *time.Duration {
	return &value
}

func firstNonEmpty(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

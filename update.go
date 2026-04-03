package main

import (
	"fmt"

	"github.com/melbahja/goph"
)

const defaultSSHPort = 22

var (
	resolveConnectionConfigFn = resolveConnectionConfig
	dialSSHFn                 = dialSSH
	deploySystemdUpdateFn     = deploySystemdUpdate
)

func SystemdUpdate(localFile, remoteService, remoteHost string, sshOptions sshCLIOptions) error {
	if err := validateLocalFile(localFile); err != nil {
		return err
	}

	cfg, err := resolveConnectionConfigFn(remoteHost, sshOptions)
	if err != nil {
		return err
	}

	client, err := dialSSHFn(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	return deploySystemdUpdateFn(client, localFile, remoteService)
}

func resolveConnectionConfig(remoteHost string, sshOptions sshCLIOptions) (*HostConfig, error) {
	userOverride, hostAlias, portOverride := parseUserHostPort(remoteHost)

	cfg, err := resolveSSHConfig(hostAlias, sshOptions.ConfigPath, sshOptions.ConfigPathSet)
	if err != nil {
		return nil, err
	}

	if err := applyConnectionOverrides(cfg, userOverride, portOverride, sshOptions); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = defaultSSHPort
	}
	return cfg, nil
}

func applyConnectionOverrides(cfg *HostConfig, userOverride string, portOverride int, sshOptions sshCLIOptions) error {
	if userOverride != "" {
		cfg.User = userOverride
	}
	if portOverride > 0 {
		cfg.Port = portOverride
	}

	if err := applySSHCLIOptions(cfg, sshOptions); err != nil {
		return err
	}
	return nil
}

func deploySystemdUpdate(client *goph.Client, localFile, remoteService string) error {
	execPath, err := fetchExecStartPath(client, remoteService)
	if err != nil {
		return err
	}
	fmt.Printf("ExecStart path: %s\n", execPath)

	tmpRemoteFile, err := uploadWithProgress(client, localFile)
	if err != nil {
		return err
	}

	out, err := client.Run(composeUpdateCommand(execPath, remoteService, tmpRemoteFile))
	if err != nil {
		return fmt.Errorf("update failed: %v, output: %s", err, string(out))
	}

	fmt.Printf("Service restarted: %s\n", remoteService)
	return nil
}

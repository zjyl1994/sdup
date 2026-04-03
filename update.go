package main

import (
	"fmt"

	"github.com/melbahja/goph"
)

func SystemdUpdate(localFile, remoteService, remoteHost string, remotePort int) error {
	cfg, err := resolveConnectionConfig(remoteHost, remotePort)
	if err != nil {
		return err
	}

	client, err := dialSSH(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	return deploySystemdUpdate(client, localFile, remoteService)
}

func resolveConnectionConfig(remoteHost string, remotePort int) (*HostConfig, error) {
	userOverride, hostAlias, portOverride := parseUserHostPort(remoteHost)

	cfg, err := resolveSSHConfig(hostAlias, remotePort)
	if err != nil {
		return nil, err
	}

	applyConnectionOverrides(cfg, userOverride, portOverride, remotePort)
	return cfg, nil
}

func applyConnectionOverrides(cfg *HostConfig, userOverride string, portOverride, remotePort int) {
	if userOverride != "" {
		cfg.User = userOverride
	}
	if remotePort > 0 {
		cfg.Port = remotePort
	} else if portOverride > 0 {
		cfg.Port = portOverride
	}
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

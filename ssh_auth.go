package main

import (
	"errors"
	"os"
	"strings"

	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
)

func buildAuthChain(cfg *HostConfig) []goph.Auth {
	chain := loadKeyAuths(cfg.IdentityFiles, getKeyPassphrase())

	if agentAuth, ok := buildAgentAuth(cfg); ok {
		chain = append(chain, agentAuth)
	}
	if passAuth, ok := getPasswordAuth(); ok {
		chain = append(chain, passAuth)
	}

	return chain
}

func loadKeyAuths(identityFiles []string, passphrase string) []goph.Auth {
	auths := make([]goph.Auth, 0, len(identityFiles))
	for _, identityFile := range identityFiles {
		if !fileExists(identityFile) {
			continue
		}
		if auth, err := goph.Key(identityFile, passphrase); err == nil {
			auths = append(auths, auth)
		}
	}
	return auths
}

func buildAgentAuth(cfg *HostConfig) (goph.Auth, bool) {
	if cfg.IdentitiesOnly || cfg.AgentSocket == "none" {
		return nil, false
	}

	socket := resolveAgentSocket(cfg)
	if strings.TrimSpace(socket) == "" {
		return nil, false
	}

	auth, err := useAgentWithSocket(socket)
	if err != nil {
		return nil, false
	}
	return auth, true
}

func resolveAgentSocket(cfg *HostConfig) string {
	if cfg.AgentSocket != "" {
		return cfg.AgentSocket
	}
	return os.Getenv("SSH_AUTH_SOCK")
}

func useAgentWithSocket(sock string) (goph.Auth, error) {
	origin, hadOrigin := os.LookupEnv("SSH_AUTH_SOCK")
	if err := os.Setenv("SSH_AUTH_SOCK", sock); err != nil {
		return nil, err
	}

	auth, err := goph.UseAgent()
	if hadOrigin {
		_ = os.Setenv("SSH_AUTH_SOCK", origin)
	} else {
		_ = os.Unsetenv("SSH_AUTH_SOCK")
	}

	return auth, err
}

func getKeyPassphrase() string {
	return os.Getenv("SDUP_SSH_KEY_PASSPHRASE")
}

func getPasswordAuth() (goph.Auth, bool) {
	password := os.Getenv("SDUP_SSH_PASSWORD")
	if strings.TrimSpace(password) == "" {
		return nil, false
	}
	return goph.Password(password), true
}

func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}

	message := err.Error()
	return strings.Contains(message, "unable to authenticate") ||
		strings.Contains(message, "no supported methods remain") ||
		strings.Contains(message, "handshake failed")
}

func dialSSH(cfg *HostConfig) (*goph.Client, error) {
	authChain := buildAuthChain(cfg)
	if len(authChain) == 0 {
		return nil, errors.New("no valid SSH auth method found")
	}

	var client *goph.Client
	var connErr error
	for _, auth := range authChain {
		client, connErr = goph.NewConn(&goph.Config{
			User:     cfg.User,
			Addr:     cfg.Hostname,
			Port:     uint(cfg.Port),
			Auth:     auth,
			Callback: ssh.InsecureIgnoreHostKey(),
		})
		if connErr == nil {
			return client, nil
		}
		if !isAuthFailure(connErr) {
			return nil, connErr
		}
	}

	return nil, connErr
}

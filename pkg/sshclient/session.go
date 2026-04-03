package sshclient

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/melbahja/goph"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type gophSession struct {
	client *goph.Client
}

func Dial(remote string, options Options) (Session, error) {
	cfg, err := resolveConnectionConfig(remote, options)
	if err != nil {
		return nil, err
	}

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
			return &gophSession{client: client}, nil
		}
		if !isAuthFailure(connErr) {
			return nil, connErr
		}
	}

	return nil, connErr
}

func (s *gophSession) Run(cmd string) ([]byte, error) {
	return s.client.Run(cmd)
}

func (s *gophSession) Upload(localPath, remotePath string, opts UploadOptions) error {
	localFile, totalSize, err := openLocalFileForUpload(localPath)
	if err != nil {
		return err
	}
	defer localFile.Close()

	sftpClient, err := s.client.NewSftp(sftp.MaxPacket(1 << 15))
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		return err
	}
	defer remoteFile.Close()

	return copyWithProgress(localFile, remoteFile, localPath, remotePath, totalSize, opts.OnProgress)
}

func (s *gophSession) Close() error {
	return s.client.Close()
}

func buildAuthChain(cfg *hostConfig) []goph.Auth {
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

func buildAgentAuth(cfg *hostConfig) (goph.Auth, bool) {
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

func resolveAgentSocket(cfg *hostConfig) string {
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

func openLocalFileForUpload(localPath string) (*os.File, int64, error) {
	localFile, err := os.Open(localPath)
	if err != nil {
		return nil, 0, err
	}

	stat, err := localFile.Stat()
	if err != nil {
		localFile.Close()
		return nil, 0, err
	}

	return localFile, stat.Size(), nil
}

func copyWithProgress(src io.Reader, dst io.Writer, localPath, remotePath string, totalSize int64, onProgress func(UploadProgress)) error {
	buf := make([]byte, 128*1024)
	var sent int64

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}

			sent += int64(n)
			emitUploadProgress(onProgress, UploadProgress{
				LocalPath:  localPath,
				RemotePath: remotePath,
				Sent:       sent,
				Total:      totalSize,
			})
		}

		if readErr != nil {
			if readErr == io.EOF {
				emitUploadProgress(onProgress, UploadProgress{
					LocalPath:  localPath,
					RemotePath: remotePath,
					Sent:       sent,
					Total:      totalSize,
					Done:       true,
				})
				return nil
			}
			return readErr
		}
	}
}

func emitUploadProgress(onProgress func(UploadProgress), progress UploadProgress) {
	if onProgress == nil {
		return
	}
	onProgress(progress)
}

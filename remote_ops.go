package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/melbahja/goph"
	"github.com/pkg/sftp"
)

var execStartPathPattern = regexp.MustCompile(`path=([^ ;]+)`)

func fetchExecStartPath(client *goph.Client, unit string) (string, error) {
	out, err := client.Run(fmt.Sprintf("systemctl show %s -p ExecStart", unit))
	if err != nil {
		return "", err
	}
	return extractExecStartPath(strings.TrimSpace(string(out)))
}

func extractExecStartPath(line string) (string, error) {
	if !strings.HasPrefix(line, "ExecStart=") {
		return "", errors.New("unexpected systemctl output")
	}

	value := strings.TrimPrefix(line, "ExecStart=")
	if matches := execStartPathPattern.FindStringSubmatch(value); len(matches) == 2 {
		return matches[1], nil
	}

	tokens := strings.Fields(value)
	if len(tokens) > 0 && strings.HasPrefix(tokens[0], "/") {
		return tokens[0], nil
	}

	return "", errors.New("ExecStart path not found")
}

func uploadWithProgress(client *goph.Client, localPath string) (string, error) {
	localFile, totalSize, err := openLocalFileForUpload(localPath)
	if err != nil {
		return "", err
	}
	defer localFile.Close()

	sftpClient, err := client.NewSftp(sftp.MaxPacket(1 << 15))
	if err != nil {
		return "", err
	}
	defer sftpClient.Close()

	remoteFilePath, err := createRemoteTempFilePath(client, localPath)
	if err != nil {
		return "", err
	}

	remoteFile, err := sftpClient.Create(remoteFilePath)
	if err != nil {
		return "", err
	}
	defer remoteFile.Close()

	if err := copyWithProgress(localFile, remoteFile, totalSize); err != nil {
		return "", err
	}

	fmt.Printf("\nUpload complete: %s -> %s\n", localPath, remoteFilePath)
	return remoteFilePath, nil
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

func createRemoteTempFilePath(client *goph.Client, localPath string) (string, error) {
	out, err := client.Run("mktemp -d -t sdup.XXXXXX")
	if err != nil {
		return "", err
	}

	remoteDir := strings.TrimSpace(string(out))
	return filepath.Join(remoteDir, filepath.Base(localPath)), nil
}

func copyWithProgress(src io.Reader, dst io.Writer, totalSize int64) error {
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
			pct := float64(sent) / float64(totalSize) * 100
			fmt.Printf("Uploading: %.1f%%\r", pct)
		}

		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func composeUpdateCommand(execPath, service, tmpFile string) string {
	dir := filepath.Dir(tmpFile)
	return fmt.Sprintf(
		"trap 'rm -f %s; rmdir %s 2>/dev/null || true' EXIT; set -e; sudo install -m 0755 -T %s %s && sudo systemctl restart %s",
		tmpFile, dir, tmpFile, execPath, service,
	)
}

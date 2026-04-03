package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/melbahja/goph"
	"github.com/pkg/sftp"
)

var execStartPathPattern = regexp.MustCompile(`path=([^ ;]+)`)

const progressRefreshInterval = 200 * time.Millisecond
const progressBarWidth = 24

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

	fmt.Print(renderUploadStart(totalSize))
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
	lastDisplayedAt := time.Now()
	lastDisplayedBytes := int64(0)
	lastRenderedWidth := 0

	printProgress := func(force bool) {
		now := time.Now()
		if !force && now.Sub(lastDisplayedAt) < progressRefreshInterval {
			return
		}

		elapsed := now.Sub(lastDisplayedAt)
		if elapsed <= 0 {
			elapsed = time.Nanosecond
		}

		rate := float64(sent-lastDisplayedBytes) / elapsed.Seconds()
		line := renderUploadProgress(sent, totalSize, rate)
		output, renderedWidth := formatProgressOutput(line, lastRenderedWidth)
		fmt.Print(output)
		lastRenderedWidth = renderedWidth
		lastDisplayedAt = now
		lastDisplayedBytes = sent
	}

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
			printProgress(false)
		}

		if readErr != nil {
			if readErr == io.EOF {
				printProgress(true)
				return nil
			}
			return readErr
		}
	}
}

func renderUploadProgress(sent, totalSize int64, rate float64) string {
	pct := 100.0
	if totalSize > 0 {
		pct = float64(sent) / float64(totalSize) * 100
	}
	return fmt.Sprintf(
		"Uploading: [%s] %.1f%%  %s/s",
		renderProgressBar(sent, totalSize, progressBarWidth),
		pct,
		formatByteSize(rate),
	)
}

func renderUploadStart(totalSize int64) string {
	return fmt.Sprintf("Upload size: %s\n", formatByteSize(float64(totalSize)))
}

func renderProgressBar(sent, totalSize int64, width int) string {
	if width <= 0 {
		return ""
	}
	if totalSize <= 0 {
		return strings.Repeat("=", width)
	}

	filled := int(float64(sent) / float64(totalSize) * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}

	return strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
}

func formatProgressOutput(line string, previousWidth int) (string, int) {
	renderedWidth := len(line)
	if renderedWidth < previousWidth {
		line += strings.Repeat(" ", previousWidth-renderedWidth)
		renderedWidth = previousWidth
	}
	return line + "\r", renderedWidth
}

func formatByteSize(size float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%.0f %s", size, units[unit])
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func composeUpdateCommand(execPath, service, tmpFile string) string {
	dir := filepath.Dir(tmpFile)
	return fmt.Sprintf(
		"trap 'rm -f %s; rmdir %s 2>/dev/null || true' EXIT; set -e; sudo install -m 0755 -T %s %s && sudo systemctl restart %s",
		tmpFile, dir, tmpFile, execPath, service,
	)
}

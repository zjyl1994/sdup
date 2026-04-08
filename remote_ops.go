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

	"github.com/zjyl1994/sdup/pkg/sshclient"
)

var execStartPathPattern = regexp.MustCompile(`path=([^ ;]+)`)

const progressRefreshInterval = 200 * time.Millisecond
const progressBarWidth = 24

func fetchExecStartPath(session sshclient.Session, unit string) (string, error) {
	out, err := session.Run(fmt.Sprintf("systemctl show %s -p ExecStart", unit))
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

func uploadWithProgress(session sshclient.Session, localPath string, totalSize int64) (string, error) {
	return uploadWithProgressToWriter(session, localPath, totalSize, os.Stdout)
}

func uploadWithProgressToWriter(session sshclient.Session, localPath string, totalSize int64, writer io.Writer) (string, error) {
	remoteDir, remoteFilePath, err := createRemoteTempFilePath(session, localPath)
	if err != nil {
		return "", err
	}

	renderer := newUploadProgressRenderer(writer)
	renderer.Start(totalSize)

	if err := session.Upload(localPath, remoteFilePath, sshclient.UploadOptions{
		OnProgress: renderer.Update,
	}); err != nil {
		renderer.Finish()
		if cleanupErr := cleanupRemoteTempDir(session, remoteDir); cleanupErr != nil {
			return "", errors.Join(err, cleanupErr)
		}
		return "", err
	}

	renderer.Finish()
	fmt.Fprintf(writer, "Upload complete: %s -> %s\n", localPath, remoteFilePath)
	return remoteFilePath, nil
}

func localFileSize(localPath string) (int64, error) {
	stat, err := os.Stat(localPath)
	if err != nil {
		return 0, err
	}
	return stat.Size(), nil
}

func createRemoteTempFilePath(session sshclient.Session, localPath string) (string, string, error) {
	out, err := session.Run("mktemp -d -t sdup.XXXXXX")
	if err != nil {
		return "", "", err
	}

	remoteDir := strings.TrimSpace(string(out))
	return remoteDir, filepath.Join(remoteDir, filepath.Base(localPath)), nil
}

func cleanupRemoteTempDir(session sshclient.Session, remoteDir string) error {
	if strings.TrimSpace(remoteDir) == "" {
		return nil
	}

	_, err := session.Run("rm -rf -- " + shellQuote(remoteDir))
	if err != nil {
		return fmt.Errorf("cleanup remote temp dir %q: %w", remoteDir, err)
	}
	return nil
}

type uploadProgressRenderer struct {
	writer             io.Writer
	startedAt          time.Time
	lastDisplayedAt    time.Time
	lastDisplayedBytes int64
	lastRenderedWidth  int
}

func newUploadProgressRenderer(writer io.Writer) *uploadProgressRenderer {
	return &uploadProgressRenderer{writer: writer}
}

func (r *uploadProgressRenderer) Start(totalSize int64) {
	now := time.Now()
	r.startedAt = now
	r.lastDisplayedAt = now
}

func (r *uploadProgressRenderer) Update(progress sshclient.UploadProgress) {
	now := time.Now()
	if !progress.Done && now.Sub(r.lastDisplayedAt) < progressRefreshInterval {
		return
	}

	deltaBytes := progress.Sent - r.lastDisplayedBytes
	if progress.Done && deltaBytes == 0 && r.lastRenderedWidth > 0 {
		return
	}

	elapsed := now.Sub(r.lastDisplayedAt)
	if elapsed <= 0 {
		elapsed = time.Nanosecond
	}

	rate := float64(deltaBytes) / elapsed.Seconds()
	if progress.Done && deltaBytes == 0 {
		totalElapsed := now.Sub(r.startedAt)
		if totalElapsed <= 0 {
			totalElapsed = time.Nanosecond
		}
		rate = float64(progress.Sent) / totalElapsed.Seconds()
	}
	line := renderUploadProgress(progress.Sent, progress.Total, rate)
	output, renderedWidth := formatProgressOutput(line, r.lastRenderedWidth)
	fmt.Fprint(r.writer, output)
	r.lastRenderedWidth = renderedWidth
	r.lastDisplayedAt = now
	r.lastDisplayedBytes = progress.Sent
}

func (r *uploadProgressRenderer) Finish() {
	if r.lastRenderedWidth == 0 {
		return
	}
	fmt.Fprintln(r.writer)
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

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
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

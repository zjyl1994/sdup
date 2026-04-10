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
var healthCheckSleepFn = time.Sleep

const progressRefreshInterval = 200 * time.Millisecond
const progressBarWidth = 24

type deploymentCheck struct {
	execPath   string
	backupPath string
}

func fetchExecStartPath(session sshclient.Session, unit string) (string, error) {
	out, err := runRemoteCommand(session, fetchExecStartCommand(unit), fmt.Sprintf("inspect systemd service %q", unit))
	if err != nil {
		return "", err
	}
	return extractExecStartPath(strings.TrimSpace(string(out)))
}

func runDeploymentChecks(session sshclient.Session, service string) (*deploymentCheck, error) {
	execPath, err := fetchExecStartPath(session, service)
	if err != nil {
		return nil, err
	}
	if _, err := runRemoteCommand(session, ensureSudoCommand(), "verify sudo access"); err != nil {
		return nil, err
	}
	if _, err := runRemoteCommand(session, checkRemoteExecutableCommand(execPath), fmt.Sprintf("verify remote executable %q", execPath)); err != nil {
		return nil, err
	}

	return &deploymentCheck{
		execPath: execPath,
	}, nil
}

func backupPathForUploadedBinary(stagingPath, execPath string) string {
	stagingDir := filepath.Dir(stagingPath)
	uploadName := filepath.Base(stagingPath)
	backupBase := filepath.Base(execPath) + ".previous"
	if backupBase != uploadName {
		return filepath.Join(stagingDir, backupBase)
	}

	for suffix := 1; ; suffix++ {
		candidate := fmt.Sprintf("%s.%d", backupBase, suffix)
		if candidate != uploadName {
			return filepath.Join(stagingDir, candidate)
		}
	}
}

func backupCurrentBinary(session sshclient.Session, execPath, backupPath string) error {
	_, err := runRemoteCommand(session, copyBinaryCommand(execPath, backupPath), fmt.Sprintf("backup current binary to %q", backupPath))
	return err
}

func cleanupBackupBinary(session sshclient.Session, backupPath string) error {
	_, err := runRemoteCommand(session, removeRemoteFileCommand(backupPath), fmt.Sprintf("cleanup backup binary %q", backupPath))
	return err
}

func installUploadedBinary(session sshclient.Session, stagingPath, execPath string) error {
	return installBinary(session, stagingPath, execPath, fmt.Sprintf("install uploaded binary to %q", execPath))
}

func restartService(session sshclient.Session, service string) error {
	_, err := runRemoteCommand(session, restartServiceCommand(service), fmt.Sprintf("restart service %q", service))
	return err
}

func verifyServiceActive(session sshclient.Session, service string) error {
	_, err := runRemoteCommand(session, verifyServiceActiveCommand(service), fmt.Sprintf("verify service %q is active", service))
	return err
}

func verifyServiceStable(session sshclient.Session, service string, waitWindow time.Duration) error {
	remaining := waitWindow
	for {
		if err := verifyServiceActive(session, service); err == nil {
			break
		} else if remaining <= 0 {
			return err
		}

		sleepFor := healthCheckPollInterval
		if remaining < sleepFor {
			sleepFor = remaining
		}
		healthCheckSleepFn(sleepFor)
		remaining -= sleepFor
	}

	for remaining > 0 {
		sleepFor := healthCheckPollInterval
		if remaining < sleepFor {
			sleepFor = remaining
		}
		healthCheckSleepFn(sleepFor)
		remaining -= sleepFor
		if err := verifyServiceActive(session, service); err != nil {
			return err
		}
	}
	return nil
}

func fetchRecentServiceLogs(session sshclient.Session, service string, lines int) (string, error) {
	out, err := session.Run(fetchRecentLogsCommand(service, lines))
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		if trimmed == "" {
			return "", fmt.Errorf("fetch recent logs for %q: %w", service, err)
		}
		return trimmed, fmt.Errorf("fetch recent logs for %q: %w; output: %s", service, err, trimmed)
	}
	return trimmed, nil
}

func rollbackBinary(session sshclient.Session, service, backupPath, execPath string, waitWindow time.Duration) (string, error) {
	if err := installBinary(session, backupPath, execPath, fmt.Sprintf("restore backup for service %q", service)); err != nil {
		return backupPath, err
	}
	if err := restartService(session, service); err != nil {
		return backupPath, err
	}
	if err := verifyServiceStable(session, service, waitWindow); err != nil {
		return backupPath, err
	}
	return backupPath, nil
}

func installBinary(session sshclient.Session, srcPath, dstPath, action string) (err error) {
	tempPath, err := createInstallTempPath(session, dstPath)
	if err != nil {
		return err
	}
	cleanupTemp := true
	defer func() {
		if !cleanupTemp {
			return
		}
		cleanupErr := cleanupInstallTempPath(session, tempPath)
		if cleanupErr == nil {
			return
		}
		if err == nil {
			err = cleanupErr
			return
		}
		err = errors.Join(err, cleanupErr)
	}()

	if _, err := runRemoteCommand(session, copyBinaryCommand(srcPath, tempPath), fmt.Sprintf("stage binary for %s", action)); err != nil {
		return err
	}
	if _, err := runRemoteCommand(session, copyFileModeCommand(dstPath, tempPath), fmt.Sprintf("preserve mode for %s", action)); err != nil {
		return err
	}
	if _, err := runRemoteCommand(session, copyFileOwnerCommand(dstPath, tempPath), fmt.Sprintf("preserve owner for %s", action)); err != nil {
		return err
	}
	if _, err := runRemoteCommand(session, moveRemoteFileCommand(tempPath, dstPath), action); err != nil {
		return err
	}

	cleanupTemp = false
	return nil
}

type remoteStaging struct {
	dir      string
	filePath string
}

func (s *remoteStaging) Cleanup(session sshclient.Session) error {
	if s == nil {
		return nil
	}
	return cleanupRemoteTempDir(session, s.dir)
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

func uploadWithProgress(session sshclient.Session, localPath string, totalSize int64) (*remoteStaging, error) {
	return uploadWithProgressToWriter(session, localPath, totalSize, os.Stdout)
}

func uploadWithProgressToWriter(session sshclient.Session, localPath string, totalSize int64, writer io.Writer) (*remoteStaging, error) {
	staging, err := createRemoteTempFilePath(session, localPath)
	if err != nil {
		return nil, err
	}

	renderer := newUploadProgressRenderer(writer)
	renderer.Start()

	if err := session.Upload(localPath, staging.filePath, sshclient.UploadOptions{
		OnProgress: renderer.Update,
	}); err != nil {
		renderer.Finish()
		if cleanupErr := staging.Cleanup(session); cleanupErr != nil {
			return nil, errors.Join(err, cleanupErr)
		}
		return nil, err
	}

	renderer.Finish()
	fmt.Fprintf(writer, "Upload complete: %s -> %s\n", localPath, staging.filePath)
	return staging, nil
}

func localFileSize(localPath string) (int64, error) {
	stat, err := os.Stat(localPath)
	if err != nil {
		return 0, err
	}
	return stat.Size(), nil
}

func createRemoteTempFilePath(session sshclient.Session, localPath string) (*remoteStaging, error) {
	out, err := session.Run("mktemp -d -t sdup.XXXXXX")
	if err != nil {
		return nil, err
	}

	remoteDir := strings.TrimSpace(string(out))
	return &remoteStaging{
		dir:      remoteDir,
		filePath: filepath.Join(remoteDir, filepath.Base(localPath)),
	}, nil
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

func createInstallTempPath(session sshclient.Session, dstPath string) (string, error) {
	out, err := runRemoteCommand(session, createInstallTempFileCommand(dstPath), fmt.Sprintf("create install temp file for %q", dstPath))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func cleanupInstallTempPath(session sshclient.Session, tempPath string) error {
	if strings.TrimSpace(tempPath) == "" {
		return nil
	}
	_, err := runRemoteCommand(session, removeRemoteFileCommand(tempPath), fmt.Sprintf("cleanup install temp file %q", tempPath))
	return err
}

func runRemoteCommand(session sshclient.Session, cmd, action string) ([]byte, error) {
	out, err := session.Run(cmd)
	if err == nil {
		return out, nil
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return out, fmt.Errorf("%s: %w", action, err)
	}
	return out, fmt.Errorf("%s: %w; output: %s", action, err, trimmed)
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

func (r *uploadProgressRenderer) Start() {
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

func fetchExecStartCommand(service string) string {
	return fmt.Sprintf("systemctl show %s -p ExecStart", shellQuote(service))
}

func ensureSudoCommand() string {
	return "sudo -n true"
}

func checkRemoteExecutableCommand(execPath string) string {
	return "sudo -n test -x " + shellQuote(execPath)
}

func removeRemoteFileCommand(path string) string {
	return "sudo -n rm -f -- " + shellQuote(path)
}

func copyBinaryCommand(execPath, backupPath string) string {
	return fmt.Sprintf("sudo -n cp -- %s %s", shellQuote(execPath), shellQuote(backupPath))
}

func createInstallTempFileCommand(dstPath string) string {
	templatePath := filepath.Join(filepath.Dir(dstPath), "."+filepath.Base(dstPath)+".sdup.XXXXXX")
	return "sudo -n mktemp " + shellQuote(templatePath)
}

func copyFileModeCommand(referencePath, targetPath string) string {
	return fmt.Sprintf("sudo -n chmod --reference=%s -- %s", shellQuote(referencePath), shellQuote(targetPath))
}

func copyFileOwnerCommand(referencePath, targetPath string) string {
	return fmt.Sprintf("sudo -n chown --reference=%s -- %s", shellQuote(referencePath), shellQuote(targetPath))
}

func moveRemoteFileCommand(srcPath, dstPath string) string {
	return fmt.Sprintf("sudo -n mv -fT -- %s %s", shellQuote(srcPath), shellQuote(dstPath))
}

func restartServiceCommand(service string) string {
	return fmt.Sprintf("sudo -n systemctl restart %s", shellQuote(service))
}

func verifyServiceActiveCommand(service string) string {
	return fmt.Sprintf("sudo -n systemctl is-active %s", shellQuote(service))
}

func fetchRecentLogsCommand(service string, lines int) string {
	return fmt.Sprintf("sudo -n journalctl -u %s -n %d --no-pager", shellQuote(service), lines)
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

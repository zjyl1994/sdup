package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zjyl1994/sdup/pkg/sshclient"
)

func TestRemoteOpsExtractExecStartPath(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    string
		wantErr bool
	}{
		{
			name: "structured path",
			line: "ExecStart={ path=/usr/local/bin/app ; argv[]=/usr/local/bin/app }",
			want: "/usr/local/bin/app",
		},
		{
			name: "plain path fallback",
			line: "ExecStart=/usr/bin/app --serve",
			want: "/usr/bin/app",
		},
		{
			name:    "unexpected prefix",
			line:    "SomethingElse=/usr/bin/app",
			wantErr: true,
		},
		{
			name:    "missing path",
			line:    "ExecStart=app --serve",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractExecStartPath(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got path %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractExecStartPath returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRemoteOpsRenderUploadProgress(t *testing.T) {
	got := renderUploadProgress(512*1024, 1024*1024, 2*1024*1024)
	want := "Uploading: [============            ] 50.0%  2.0 MiB/s"

	if got != want {
		t.Fatalf("renderUploadProgress() = %q, want %q", got, want)
	}
}

func TestRemoteOpsRenderUploadStart(t *testing.T) {
	got := renderUploadStart(1024 * 1024)
	want := "Upload size: 1.0 MiB\n"

	if got != want {
		t.Fatalf("renderUploadStart() = %q, want %q", got, want)
	}
}

func TestRemoteOpsRenderProgressBar(t *testing.T) {
	tests := []struct {
		name      string
		sent      int64
		totalSize int64
		width     int
		want      string
	}{
		{
			name:      "half",
			sent:      50,
			totalSize: 100,
			width:     10,
			want:      "=====     ",
		},
		{
			name:      "full",
			sent:      100,
			totalSize: 100,
			width:     10,
			want:      "==========",
		},
		{
			name:      "unknown total",
			sent:      0,
			totalSize: 0,
			width:     5,
			want:      "=====",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renderProgressBar(tt.sent, tt.totalSize, tt.width); got != tt.want {
				t.Fatalf("renderProgressBar(%d, %d, %d) = %q, want %q", tt.sent, tt.totalSize, tt.width, got, tt.want)
			}
		})
	}
}

func TestRemoteOpsFormatProgressOutputClearsPreviousTail(t *testing.T) {
	prevLine := renderUploadProgress(512*1024, 1024*1024, 123.4*1024*1024)
	line := renderUploadProgress(512*1024, 1024*1024, 99.9*1024*1024)
	got, width := formatProgressOutput(line, len(prevLine))
	want := line + " " + "\r"

	if got != want {
		t.Fatalf("formatProgressOutput() = %q, want %q", got, want)
	}
	if width != len(prevLine) {
		t.Fatalf("width = %d, want %d", width, len(prevLine))
	}
}

func TestRemoteOpsFormatByteSize(t *testing.T) {
	tests := []struct {
		name string
		size float64
		want string
	}{
		{
			name: "bytes",
			size: 999,
			want: "999 B",
		},
		{
			name: "kibibytes",
			size: 1536,
			want: "1.5 KiB",
		},
		{
			name: "mebibytes",
			size: 5 * 1024 * 1024,
			want: "5.0 MiB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatByteSize(tt.size); got != tt.want {
				t.Fatalf("formatByteSize(%v) = %q, want %q", tt.size, got, tt.want)
			}
		})
	}
}

func TestUploadWithProgressCleansUpRemoteTempDirOnUploadError(t *testing.T) {
	localFile := filepathForTempFile(t)
	session := &fakeRemoteSession{
		uploadErr: errors.New("upload failed"),
		commandResults: map[string][]commandResult{
			"mktemp -d -t sdup.XXXXXX": {{output: []byte("/tmp/sdup.testdir\n")}},
		},
	}
	var out bytes.Buffer

	totalSize, err := localFileSize(localFile)
	if err != nil {
		t.Fatalf("localFileSize returned error: %v", err)
	}

	_, err = uploadWithProgressToWriter(session, localFile, totalSize, &out)
	if !errors.Is(err, session.uploadErr) {
		t.Fatalf("uploadWithProgressToWriter error = %v, want %v", err, session.uploadErr)
	}
	if count := countCommand(session.runCommands, "rm -rf -- '/tmp/sdup.testdir'"); count != 1 {
		t.Fatalf("cleanup command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
}

func TestDeploySystemdUpdateCleansUpRemoteTempDirWhenRunFails(t *testing.T) {
	localFile := filepathForTempFile(t)
	execPath := "/usr/local/bin/api"
	session := &fakeRemoteSession{
		commandResults: baseDeployCommandResults(localFile, "api", execPath),
	}
	session.commandResults[restartServiceCommand("api")] = []commandResult{{err: errors.New("run failed")}}

	totalSize, err := localFileSize(localFile)
	if err != nil {
		t.Fatalf("localFileSize returned error: %v", err)
	}

	err = deploySystemdUpdate(session, localFile, "api", totalSize, deploymentTestOptions())
	if err == nil {
		t.Fatal("deploySystemdUpdate returned nil error")
	}
	if count := countCommand(session.runCommands, "rm -rf -- '/tmp/sdup.testdir'"); count != 1 {
		t.Fatalf("cleanup command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
	if count := countCommand(session.runCommands, fetchRecentLogsCommand("api", defaultDeployLogLines)); count != 1 {
		t.Fatalf("recent logs command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
}

func TestDeploySystemdUpdateCleansUpOnceAfterSuccess(t *testing.T) {
	localFile := filepathForTempFile(t)
	execPath := "/usr/local/bin/api"
	stagingPath := filepath.Join("/tmp/sdup.testdir", filepath.Base(localFile))
	backupPath := backupPathForUploadedBinary(stagingPath, execPath)
	session := &fakeRemoteSession{
		commandResults: baseDeployCommandResults(localFile, "api", execPath),
	}

	totalSize, err := localFileSize(localFile)
	if err != nil {
		t.Fatalf("localFileSize returned error: %v", err)
	}

	if err := deploySystemdUpdate(session, localFile, "api", totalSize, deploymentTestOptions()); err != nil {
		t.Fatalf("deploySystemdUpdate returned error: %v", err)
	}
	if count := countCommand(session.runCommands, "rm -rf -- '/tmp/sdup.testdir'"); count != 1 {
		t.Fatalf("cleanup command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
	if count := countCommand(session.runCommands, removeRemoteFileCommand(backupPath)); count != 1 {
		t.Fatalf("backup cleanup command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
	if count := countCommand(session.runCommands, fetchRecentLogsCommand("api", defaultDeployLogLines)); count != 1 {
		t.Fatalf("recent logs command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
}

func TestDeploySystemdUpdateRollsBackToPreviousBackupWhenServiceFailsHealthCheck(t *testing.T) {
	localFile := filepathForTempFile(t)
	execPath := "/usr/local/bin/api"
	stagingPath := filepath.Join("/tmp/sdup.testdir", filepath.Base(localFile))
	backupPath := backupPathForUploadedBinary(stagingPath, execPath)
	session := &fakeRemoteSession{
		commandResults: baseDeployCommandResults(localFile, "api", execPath),
	}
	session.commandResults[createInstallTempFileCommand(execPath)] = []commandResult{
		{output: []byte(installTempPathForTest(execPath) + "\n")},
		{output: []byte(installTempPathForTest(execPath) + "\n")},
	}
	session.commandResults[verifyServiceActiveCommand("api")] = []commandResult{{output: []byte("active\n")}, {err: errors.New("inactive")}, {output: []byte("active\n")}}

	totalSize, err := localFileSize(localFile)
	if err != nil {
		t.Fatalf("localFileSize returned error: %v", err)
	}

	origSleep := healthCheckSleepFn
	healthCheckSleepFn = func(time.Duration) {}
	defer func() { healthCheckSleepFn = origSleep }()

	err = deploySystemdUpdate(session, localFile, "api", totalSize, deploymentOptions{
		logLines:        defaultDeployLogLines,
		healthCheckWait: 1500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("deploySystemdUpdate returned nil error")
	}
	if !strings.Contains(err.Error(), "restored backup "+backupPath) {
		t.Fatalf("deploySystemdUpdate error = %v, want rollback notice", err)
	}
	if !containsAllCommands(session.runCommands, installBinaryCommands(backupPath, execPath)) {
		t.Fatalf("rollback install commands missing; commands = %v", session.runCommands)
	}
	if count := countCommand(session.runCommands, restartServiceCommand("api")); count != 2 {
		t.Fatalf("restart command count = %d, want %d; commands = %v", count, 2, session.runCommands)
	}
	if !containsAllCommands(session.runCommands, installBinaryCommands(stagingPath, execPath)) {
		t.Fatalf("deploy install commands missing; commands = %v", session.runCommands)
	}
	if count := countCommand(session.runCommands, fetchRecentLogsCommand("api", defaultDeployLogLines)); count != 1 {
		t.Fatalf("recent logs command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
}

func TestDeploySystemdUpdateWaitsForServiceToBecomeActive(t *testing.T) {
	localFile := filepathForTempFile(t)
	execPath := "/usr/local/bin/api"
	stagingPath := filepath.Join("/tmp/sdup.testdir", filepath.Base(localFile))
	backupPath := backupPathForUploadedBinary(stagingPath, execPath)
	session := &fakeRemoteSession{
		commandResults: baseDeployCommandResults(localFile, "api", execPath),
	}
	session.commandResults[verifyServiceActiveCommand("api")] = []commandResult{
		{output: []byte("activating\n"), err: errors.New("activating")},
		{output: []byte("active\n")},
		{output: []byte("active\n")},
	}

	totalSize, err := localFileSize(localFile)
	if err != nil {
		t.Fatalf("localFileSize returned error: %v", err)
	}

	origSleep := healthCheckSleepFn
	healthCheckSleepFn = func(time.Duration) {}
	defer func() { healthCheckSleepFn = origSleep }()

	err = deploySystemdUpdate(session, localFile, "api", totalSize, deploymentOptions{
		logLines:        defaultDeployLogLines,
		healthCheckWait: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("deploySystemdUpdate returned error: %v", err)
	}
	if count := countCommand(session.runCommands, restartServiceCommand("api")); count != 1 {
		t.Fatalf("restart command count = %d, want %d; commands = %v", count, 1, session.runCommands)
	}
	if containsAllCommands(session.runCommands, installBinaryCommands(backupPath, execPath)) {
		t.Fatalf("rollback install commands should be absent; commands = %v", session.runCommands)
	}
	if count := countCommand(session.runCommands, verifyServiceActiveCommand("api")); count != 3 {
		t.Fatalf("verify command count = %d, want %d; commands = %v", count, 3, session.runCommands)
	}
}

func TestRunDeploymentChecksLeavesBackupPathEmptyBeforeUpload(t *testing.T) {
	execPath := "/usr/local/bin/api"
	session := &fakeRemoteSession{
		commandResults: map[string][]commandResult{
			fetchExecStartCommand("api"):           {{output: []byte("ExecStart=/usr/local/bin/api --serve\n")}},
			ensureSudoCommand():                    {{}},
			checkRemoteExecutableCommand(execPath): {{}},
		},
	}

	check, err := runDeploymentChecks(session, "api")
	if err != nil {
		t.Fatalf("runDeploymentChecks returned error: %v", err)
	}
	if check.execPath != execPath {
		t.Fatalf("execPath = %q, want %q", check.execPath, execPath)
	}
	if check.backupPath != "" {
		t.Fatalf("backupPath = %q, want empty before upload", check.backupPath)
	}
}

func TestBackupPathForUploadedBinaryAvoidsNameConflict(t *testing.T) {
	stagingPath := "/tmp/sdup.testdir/api.previous"
	execPath := "/usr/local/bin/api"

	got := backupPathForUploadedBinary(stagingPath, execPath)
	want := "/tmp/sdup.testdir/api.previous.1"
	if got != want {
		t.Fatalf("backupPathForUploadedBinary() = %q, want %q", got, want)
	}
}

func TestVerifyServiceStableHonorsWaitWindow(t *testing.T) {
	session := &fakeRemoteSession{
		commandResults: map[string][]commandResult{
			verifyServiceActiveCommand("api"): {{output: []byte("active\n")}, {output: []byte("active\n")}, {output: []byte("active\n")}},
		},
	}

	sleeps := 0
	origSleep := healthCheckSleepFn
	healthCheckSleepFn = func(time.Duration) { sleeps++ }
	defer func() { healthCheckSleepFn = origSleep }()

	if err := verifyServiceStable(session, "api", 1500*time.Millisecond); err != nil {
		t.Fatalf("verifyServiceStable returned error: %v", err)
	}
	if count := countCommand(session.runCommands, verifyServiceActiveCommand("api")); count != 3 {
		t.Fatalf("verify command count = %d, want %d", count, 3)
	}
	if sleeps != 2 {
		t.Fatalf("sleep count = %d, want %d", sleeps, 2)
	}
}

func TestVerifyServiceStableWaitsForServiceToBecomeActive(t *testing.T) {
	session := &fakeRemoteSession{
		commandResults: map[string][]commandResult{
			verifyServiceActiveCommand("api"): {
				{output: []byte("activating\n"), err: errors.New("activating")},
				{output: []byte("active\n")},
				{output: []byte("active\n")},
			},
		},
	}

	sleeps := 0
	origSleep := healthCheckSleepFn
	healthCheckSleepFn = func(time.Duration) { sleeps++ }
	defer func() { healthCheckSleepFn = origSleep }()

	if err := verifyServiceStable(session, "api", 1500*time.Millisecond); err != nil {
		t.Fatalf("verifyServiceStable returned error: %v", err)
	}
	if count := countCommand(session.runCommands, verifyServiceActiveCommand("api")); count != 3 {
		t.Fatalf("verify command count = %d, want %d", count, 3)
	}
	if sleeps != 2 {
		t.Fatalf("sleep count = %d, want %d", sleeps, 2)
	}
}

func TestRollbackBinaryUsesStabilityWindow(t *testing.T) {
	session := &fakeRemoteSession{
		commandResults: map[string][]commandResult{
			createInstallTempFileCommand("/usr/local/bin/api"):                                        {{output: []byte(installTempPathForTest("/usr/local/bin/api") + "\n")}},
			copyBinaryCommand("/tmp/api.previous", installTempPathForTest("/usr/local/bin/api")):      {{}},
			copyFileModeCommand("/usr/local/bin/api", installTempPathForTest("/usr/local/bin/api")):   {{}},
			copyFileOwnerCommand("/usr/local/bin/api", installTempPathForTest("/usr/local/bin/api")):  {{}},
			moveRemoteFileCommand(installTempPathForTest("/usr/local/bin/api"), "/usr/local/bin/api"): {{}},
			restartServiceCommand("api"): {{}},
			verifyServiceActiveCommand("api"): {
				{output: []byte("active\n")},
				{output: []byte("active\n")},
				{output: []byte("failed\n"), err: errors.New("failed")},
			},
		},
	}

	origSleep := healthCheckSleepFn
	healthCheckSleepFn = func(time.Duration) {}
	defer func() { healthCheckSleepFn = origSleep }()

	_, err := rollbackBinary(session, "api", "/tmp/api.previous", "/usr/local/bin/api", 1500*time.Millisecond)
	if err == nil {
		t.Fatal("rollbackBinary returned nil error")
	}
	if !containsAllCommands(session.runCommands, installBinaryCommands("/tmp/api.previous", "/usr/local/bin/api")) {
		t.Fatalf("rollback install commands missing; commands = %v", session.runCommands)
	}
	if count := countCommand(session.runCommands, verifyServiceActiveCommand("api")); count != 3 {
		t.Fatalf("verify command count = %d, want %d; commands = %v", count, 3, session.runCommands)
	}
}

func TestInstallBinaryUsesExplicitReadableSteps(t *testing.T) {
	tempPath := installTempPathForTest("/usr/local/bin/api")
	commands := installBinaryCommands("/tmp/uploaded-api", "/usr/local/bin/api")
	want := []string{
		createInstallTempFileCommand("/usr/local/bin/api"),
		copyBinaryCommand("/tmp/uploaded-api", tempPath),
		copyFileModeCommand("/usr/local/bin/api", tempPath),
		copyFileOwnerCommand("/usr/local/bin/api", tempPath),
		moveRemoteFileCommand(tempPath, "/usr/local/bin/api"),
	}
	if !equalStringSlices(commands, want) {
		t.Fatalf("installBinaryCommands = %v, want %v", commands, want)
	}
}

func TestUploadProgressRendererSkipsZeroRateDoneRedraw(t *testing.T) {
	var out bytes.Buffer
	renderer := &uploadProgressRenderer{
		writer:             &out,
		startedAt:          time.Now().Add(-2 * time.Second),
		lastDisplayedAt:    time.Now().Add(-1 * time.Second),
		lastDisplayedBytes: 1024,
		lastRenderedWidth:  10,
	}

	renderer.Update(sshclient.UploadProgress{
		Sent:  1024,
		Total: 1024,
		Done:  true,
	})

	if got := out.String(); got != "" {
		t.Fatalf("renderer output = %q, want empty string", got)
	}
}

func TestShellQuoteEscapesSingleQuotes(t *testing.T) {
	got := shellQuote("/tmp/sdup.o'reilly")
	want := "'/tmp/sdup.o'\"'\"'reilly'"

	if got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

type fakeRemoteSession struct {
	runCommands    []string
	uploadErr      error
	commandResults map[string][]commandResult
}

type commandResult struct {
	output []byte
	err    error
}

func (s *fakeRemoteSession) Run(cmd string) ([]byte, error) {
	s.runCommands = append(s.runCommands, cmd)
	if results := s.commandResults[cmd]; len(results) > 0 {
		result := results[0]
		s.commandResults[cmd] = results[1:]
		return result.output, result.err
	}
	if strings.HasPrefix(cmd, "rm -rf -- ") {
		return nil, nil
	}
	return nil, nil
}

func (s *fakeRemoteSession) Upload(localPath, remotePath string, opts sshclient.UploadOptions) error {
	return s.uploadErr
}

func (s *fakeRemoteSession) Close() error {
	return nil
}

func filepathForTempFile(t *testing.T) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "upload-*")
	if err != nil {
		t.Fatalf("CreateTemp returned error: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString("content"); err != nil {
		t.Fatalf("WriteString returned error: %v", err)
	}

	return f.Name()
}

func baseDeployCommandResults(localFile, service, execPath string) map[string][]commandResult {
	stagingPath := filepath.Join("/tmp/sdup.testdir", filepath.Base(localFile))
	backupPath := backupPathForUploadedBinary(stagingPath, execPath)
	results := map[string][]commandResult{
		fetchExecStartCommand(service):                         {{output: []byte("ExecStart=" + execPath + " --serve\n")}},
		fetchRecentLogsCommand(service, defaultDeployLogLines): {{output: []byte("recent log\n")}},
		ensureSudoCommand():                                    {{}},
		checkRemoteExecutableCommand(execPath):                 {{}},
		"mktemp -d -t sdup.XXXXXX":                             {{output: []byte("/tmp/sdup.testdir\n")}},
		copyBinaryCommand(execPath, backupPath):                {{}},
		restartServiceCommand(service):                         {{}},
		verifyServiceActiveCommand(service):                    {{output: []byte("active\n")}},
		removeRemoteFileCommand(backupPath):                    {{}},
	}
	results[createInstallTempFileCommand(execPath)] = []commandResult{{output: []byte(installTempPathForTest(execPath) + "\n")}}
	for _, cmd := range installBinaryCommands(stagingPath, execPath)[1:] {
		results[cmd] = []commandResult{{}}
	}
	return results
}

func deploymentTestOptions() deploymentOptions {
	return deploymentOptions{
		logLines:        defaultDeployLogLines,
		healthCheckWait: 0,
	}
}

func countCommand(commands []string, target string) int {
	count := 0
	for _, cmd := range commands {
		if cmd == target {
			count++
		}
	}
	return count
}

func installBinaryCommands(srcPath, dstPath string) []string {
	tempPath := installTempPathForTest(dstPath)
	return []string{
		createInstallTempFileCommand(dstPath),
		copyBinaryCommand(srcPath, tempPath),
		copyFileModeCommand(dstPath, tempPath),
		copyFileOwnerCommand(dstPath, tempPath),
		moveRemoteFileCommand(tempPath, dstPath),
	}
}

func installTempPathForTest(dstPath string) string {
	return filepath.Join(filepath.Dir(dstPath), "."+filepath.Base(dstPath)+".sdup.test")
}

func containsAllCommands(commands []string, expected []string) bool {
	for _, cmd := range expected {
		if countCommand(commands, cmd) == 0 {
			return false
		}
	}
	return true
}

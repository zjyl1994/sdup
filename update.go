package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zjyl1994/sdup/pkg/sshclient"
)

var (
	dialSSHSessionFn      = sshclient.Dial
	deploySystemdUpdateFn = deploySystemdUpdate
	reportUploadStartFn   = reportUploadStart
)

func SystemdUpdate(localFile, remoteService, remoteHost string, sshOptions sshCLIOptions, deployOpts deploymentOptions) error {
	if err := validateLocalFile(localFile); err != nil {
		return err
	}

	totalSize, err := localFileSize(localFile)
	if err != nil {
		return err
	}
	reportUploadStartFn(totalSize)

	session, err := dialSSHSessionFn(remoteHost, sshOptions)
	if err != nil {
		return err
	}
	defer session.Close()

	return deploySystemdUpdateFn(session, localFile, remoteService, totalSize, deployOpts)
}

func deploySystemdUpdate(session sshclient.Session, localFile, remoteService string, totalSize int64, deployOpts deploymentOptions) (err error) {
	report := deploymentReport{
		Service:         remoteService,
		UploadSize:      totalSize,
		BackupRootDir:   deployOpts.backupDir,
		LogLines:        deployOpts.logLines,
		HealthCheckWait: deployOpts.healthCheckWait,
		LockTimeout:     deployOpts.lockTimeout,
		FinalState:      "failed",
	}
	defer func() {
		logs, err := fetchRecentServiceLogs(session, remoteService, deployOpts.logLines)
		if err != nil {
			report.LogsError = err.Error()
		}
		report.RecentLogs = logs
		fmt.Print(report.Render())
	}()

	check, err := runDeploymentChecks(session, remoteService, deployOpts)
	if err != nil {
		report.Failure = err.Error()
		return err
	}
	report.ExecPath = check.execPath
	report.BackupPath = check.backupPath
	report.LockPath = check.lockDir
	report.ChecksPassed = true
	fmt.Printf("ExecStart path: %s\n", check.execPath)

	lockResult, err := acquireDeploymentLock(session, check.lockDir, deployOpts.lockTimeout)
	if err != nil {
		report.Failure = err.Error()
		return err
	}
	report.LockAcquired = true
	report.StaleLockRecovered = lockResult.recoveredStaleLock
	defer func() {
		releaseErr := releaseDeploymentLock(session, check.lockDir)
		if releaseErr == nil {
			return
		}
		report.LockReleaseError = releaseErr.Error()
		if err == nil {
			err = releaseErr
			return
		}
		err = errors.Join(err, releaseErr)
	}()

	staging, err := uploadWithProgress(session, localFile, totalSize)
	if err != nil {
		report.Failure = err.Error()
		return err
	}
	defer staging.Cleanup(session)
	report.StagingPath = staging.filePath
	if err := refreshDeploymentLock(session, check.lockDir); err != nil {
		report.Failure = err.Error()
		return err
	}

	if err := backupCurrentBinary(session, check.execPath, check.backupPath); err != nil {
		report.Failure = err.Error()
		return err
	}
	report.BackupCreated = true
	if err := refreshDeploymentLock(session, check.lockDir); err != nil {
		report.Failure = err.Error()
		return err
	}
	defer func() {
		cleanupErr := cleanupBackupBinary(session, check.backupPath)
		if cleanupErr == nil {
			report.BackupCleaned = true
			return
		}
		report.BackupCleanupError = cleanupErr.Error()
		if err == nil {
			err = cleanupErr
			return
		}
		err = errors.Join(err, cleanupErr)
	}()

	if err := installUploadedBinary(session, staging.filePath, check.execPath); err != nil {
		report.Failure = err.Error()
		return err
	}
	report.Installed = true
	if err := refreshDeploymentLock(session, check.lockDir); err != nil {
		report.Failure = err.Error()
		return err
	}

	if err := restartService(session, remoteService); err != nil {
		report.Failure = err.Error()
		return rollbackAfterFailedDeploy(session, remoteService, check, &report, err)
	}
	report.Restarted = true
	if err := refreshDeploymentLock(session, check.lockDir); err != nil {
		report.Failure = err.Error()
		return err
	}

	err = verifyServiceStable(session, remoteService, check.lockDir, deployOpts.healthCheckWait)
	if err != nil {
		report.Failure = err.Error()
		return rollbackAfterFailedDeploy(session, remoteService, check, &report, err)
	}
	report.HealthCheckPassed = true
	report.FinalState = "success"

	fmt.Printf("Service restarted: %s\n", remoteService)
	return nil
}

func rollbackAfterFailedDeploy(session sshclient.Session, remoteService string, check *deploymentCheck, report *deploymentReport, deployErr error) error {
	report.RollbackAttempted = true
	rollbackPath, rollbackErr := rollbackBinary(session, remoteService, check.backupPath, check.execPath)
	if rollbackErr != nil {
		report.FinalState = "failed"
		report.RollbackError = rollbackErr.Error()
		return errors.Join(
			fmt.Errorf("service failed after deploy: %w", deployErr),
			fmt.Errorf("rollback failed: %w", rollbackErr),
		)
	}

	report.RollbackSucceeded = true
	report.FinalState = "rolled back"
	return fmt.Errorf("service failed after deploy: %w; restored backup %s", deployErr, rollbackPath)
}

type deploymentReport struct {
	Service            string
	ExecPath           string
	BackupPath         string
	LockPath           string
	StagingPath        string
	BackupRootDir      string
	UploadSize         int64
	LogLines           int
	HealthCheckWait    time.Duration
	LockTimeout        time.Duration
	ChecksPassed       bool
	LockAcquired       bool
	StaleLockRecovered bool
	BackupCreated      bool
	BackupCleaned      bool
	Installed          bool
	Restarted          bool
	HealthCheckPassed  bool
	RollbackAttempted  bool
	RollbackSucceeded  bool
	FinalState         string
	Failure            string
	RollbackError      string
	BackupCleanupError string
	LockReleaseError   string
	RecentLogs         string
	LogsError          string
}

func (r deploymentReport) Render() string {
	var b strings.Builder
	b.WriteString("Deployment report:\n")
	fmt.Fprintf(&b, "  Service: %s\n", valueOrUnknown(r.Service))
	fmt.Fprintf(&b, "  Final state: %s\n", valueOrUnknown(r.FinalState))
	if r.shouldShowExecPath() {
		fmt.Fprintf(&b, "  ExecStart path: %s\n", r.ExecPath)
	}
	if r.RollbackAttempted {
		fmt.Fprintf(&b, "  Rollback: %s\n", renderRollbackStatus(r))
	}
	if r.StaleLockRecovered {
		b.WriteString("  Lock: recovered stale lock\n")
	}
	if r.Failure != "" {
		fmt.Fprintf(&b, "  Failure: %s\n", r.Failure)
	}
	if r.RollbackError != "" {
		fmt.Fprintf(&b, "  Rollback error: %s\n", r.RollbackError)
	}
	if r.BackupCleanupError != "" {
		fmt.Fprintf(&b, "  Backup cleanup error: %s\n", r.BackupCleanupError)
	}
	if r.LockReleaseError != "" {
		fmt.Fprintf(&b, "  Lock release error: %s\n", r.LockReleaseError)
	}
	fmt.Fprintf(&b, "Recent logs (%d lines):\n", r.LogLines)
	if r.RecentLogs != "" {
		b.WriteString(r.RecentLogs)
		if !strings.HasSuffix(r.RecentLogs, "\n") {
			b.WriteString("\n")
		}
	} else {
		b.WriteString("(no journal output)\n")
	}
	if r.LogsError != "" {
		fmt.Fprintf(&b, "Log fetch error: %s\n", r.LogsError)
	}
	return b.String()
}

func (r deploymentReport) shouldShowExecPath() bool {
	if strings.TrimSpace(r.ExecPath) == "" {
		return false
	}
	return r.FinalState != "success"
}

func renderRollbackStatus(report deploymentReport) string {
	if !report.RollbackAttempted {
		return "not needed"
	}
	if report.RollbackSucceeded {
		return "restored previous backup"
	}
	return "failed"
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func reportUploadStart(totalSize int64) {
	fmt.Print(renderUploadStart(totalSize))
}

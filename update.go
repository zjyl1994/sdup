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
	defer printRecentServiceLogs(session, remoteService, deployOpts.logLines)

	check, err := runDeploymentChecks(session, remoteService)
	if err != nil {
		return err
	}
	fmt.Printf("ExecStart path: %s\n", check.execPath)

	staging, err := uploadWithProgress(session, localFile, totalSize)
	if err != nil {
		return err
	}
	defer staging.Cleanup(session)
	check.backupPath = backupPathForUploadedBinary(staging.filePath, check.execPath)

	if err := backupCurrentBinary(session, check.execPath, check.backupPath); err != nil {
		return err
	}
	defer func() {
		cleanupErr := cleanupBackupBinary(session, check.backupPath)
		if cleanupErr == nil {
			return
		}
		if err == nil {
			err = cleanupErr
			return
		}
		err = errors.Join(err, cleanupErr)
	}()

	if err := installUploadedBinary(session, staging.filePath, check.execPath); err != nil {
		return err
	}

	if err := restartService(session, remoteService); err != nil {
		return rollbackAfterFailedDeploy(session, remoteService, check, deployOpts.healthCheckWait, err)
	}

	err = verifyServiceStable(session, remoteService, deployOpts.healthCheckWait)
	if err != nil {
		return rollbackAfterFailedDeploy(session, remoteService, check, deployOpts.healthCheckWait, err)
	}

	fmt.Printf("Service restarted: %s\n", remoteService)
	return nil
}

func rollbackAfterFailedDeploy(session sshclient.Session, remoteService string, check *deploymentCheck, waitWindow time.Duration, deployErr error) error {
	rollbackPath, rollbackErr := rollbackBinary(session, remoteService, check.backupPath, check.execPath, waitWindow)
	if rollbackErr != nil {
		return errors.Join(
			fmt.Errorf("service failed after deploy: %w", deployErr),
			fmt.Errorf("rollback failed: %w", rollbackErr),
		)
	}

	return fmt.Errorf("service failed after deploy: %w; restored backup %s", deployErr, rollbackPath)
}

func printRecentServiceLogs(session sshclient.Session, remoteService string, lines int) {
	if lines <= 0 {
		return
	}

	logs, err := fetchRecentServiceLogs(session, remoteService, lines)
	fmt.Printf("Recent logs (%d lines):\n", lines)
	if logs == "" {
		fmt.Println("(no journal output)")
	} else {
		fmt.Print(logs)
		if !strings.HasSuffix(logs, "\n") {
			fmt.Println()
		}
	}
	if err != nil {
		fmt.Printf("Log fetch error: %v\n", err)
	}
}

func reportUploadStart(totalSize int64) {
	fmt.Print(renderUploadStart(totalSize))
}

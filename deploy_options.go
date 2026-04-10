package main

import "time"

const defaultDeployBackupDir = "/var/tmp/sdup"
const defaultDeployLogLines = 10
const defaultHealthCheckWait = 5 * time.Second
const defaultDeployLockTimeout = 15 * time.Minute
const healthCheckPollInterval = time.Second

type deploymentOptions struct {
	backupDir          string
	backupDirSet       bool
	logLines           int
	logLinesSet        bool
	healthCheckWait    time.Duration
	healthCheckWaitSet bool
	lockTimeout        time.Duration
	lockTimeoutSet     bool
}

func defaultDeploymentOptions() deploymentOptions {
	return deploymentOptions{
		backupDir:       defaultDeployBackupDir,
		logLines:        defaultDeployLogLines,
		healthCheckWait: defaultHealthCheckWait,
		lockTimeout:     defaultDeployLockTimeout,
	}
}

func buildDeploymentOptions(opts cliOptions) deploymentOptions {
	resolved := defaultDeploymentOptions()
	if opts.deployment.backupDirSet {
		resolved.backupDir = opts.deployment.backupDir
		resolved.backupDirSet = true
	}
	if opts.deployment.logLinesSet {
		resolved.logLines = opts.deployment.logLines
		resolved.logLinesSet = true
	}
	if opts.deployment.healthCheckWaitSet {
		resolved.healthCheckWait = opts.deployment.healthCheckWait
		resolved.healthCheckWaitSet = true
	}
	if opts.deployment.lockTimeoutSet {
		resolved.lockTimeout = opts.deployment.lockTimeout
		resolved.lockTimeoutSet = true
	}
	return resolved
}

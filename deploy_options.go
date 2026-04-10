package main

import "time"

const defaultDeployBackupDir = "/var/tmp/sdup"
const defaultDeployLogLines = 5
const defaultHealthCheckWait = 5 * time.Second
const healthCheckPollInterval = time.Second

type deploymentOptions struct {
	backupDir          string
	backupDirSet       bool
	logLines           int
	logLinesSet        bool
	healthCheckWait    time.Duration
	healthCheckWaitSet bool
}

func defaultDeploymentOptions() deploymentOptions {
	return deploymentOptions{
		backupDir:       defaultDeployBackupDir,
		logLines:        defaultDeployLogLines,
		healthCheckWait: defaultHealthCheckWait,
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
	return resolved
}

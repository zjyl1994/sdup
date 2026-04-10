package main

import "time"

const defaultDeployLogLines = 5
const defaultHealthCheckWait = 5 * time.Second
const healthCheckPollInterval = time.Second

type deploymentOptions struct {
	logLines           int
	logLinesSet        bool
	healthCheckWait    time.Duration
	healthCheckWaitSet bool
}

func defaultDeploymentOptions() deploymentOptions {
	return deploymentOptions{
		logLines:        defaultDeployLogLines,
		healthCheckWait: defaultHealthCheckWait,
	}
}

func buildDeploymentOptions(opts cliOptions) deploymentOptions {
	resolved := defaultDeploymentOptions()
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

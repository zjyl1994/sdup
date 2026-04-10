package main

import "time"

const defaultDeployLogLines = 5
const defaultHealthCheckWait = 5 * time.Second
const healthCheckPollInterval = time.Second

type deploymentOptions struct {
	logLines        int
	healthCheckWait time.Duration
}

func defaultDeploymentOptions() deploymentOptions {
	return deploymentOptions{
		logLines:        defaultDeployLogLines,
		healthCheckWait: defaultHealthCheckWait,
	}
}

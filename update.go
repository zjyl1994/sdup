package main

import (
	"fmt"

	"github.com/zjyl1994/sdup/pkg/sshclient"
)

var (
	dialSSHSessionFn      = sshclient.Dial
	deploySystemdUpdateFn = deploySystemdUpdate
	reportUploadStartFn   = reportUploadStart
)

func SystemdUpdate(localFile, remoteService, remoteHost string, sshOptions sshCLIOptions) error {
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

	return deploySystemdUpdateFn(session, localFile, remoteService, totalSize)
}

func deploySystemdUpdate(session sshclient.Session, localFile, remoteService string, totalSize int64) error {
	execPath, err := fetchExecStartPath(session, remoteService)
	if err != nil {
		return err
	}
	fmt.Printf("ExecStart path: %s\n", execPath)

	tmpRemoteFile, err := uploadWithProgress(session, localFile, totalSize)
	if err != nil {
		return err
	}

	out, err := session.Run(composeUpdateCommand(execPath, remoteService, tmpRemoteFile))
	if err != nil {
		return fmt.Errorf("update failed: %v, output: %s", err, string(out))
	}

	fmt.Printf("Service restarted: %s\n", remoteService)
	return nil
}

func reportUploadStart(totalSize int64) {
	fmt.Print(renderUploadStart(totalSize))
}

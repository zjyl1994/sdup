package main

import (
	"errors"
	"testing"

	"github.com/zjyl1994/sdup/pkg/sshclient"
)

func TestSystemdUpdateSkipsSSHWhenLocalFileMissing(t *testing.T) {
	origDial := dialSSHSessionFn
	origDeploy := deploySystemdUpdateFn
	defer func() {
		dialSSHSessionFn = origDial
		deploySystemdUpdateFn = origDeploy
	}()

	dialCalled := false
	deployCalled := false

	dialSSHSessionFn = func(remoteHost string, sshOptions sshclient.Options) (sshclient.Session, error) {
		dialCalled = true
		return nil, errors.New("unexpected dial")
	}
	deploySystemdUpdateFn = func(session sshclient.Session, localFile, remoteService string) error {
		deployCalled = true
		return nil
	}

	err := SystemdUpdate("/tmp/definitely-missing-sdup-binary", "api", "prod", sshCLIOptions{})
	if err == nil {
		t.Fatal("SystemdUpdate returned nil error for missing file")
	}
	if dialCalled {
		t.Fatal("Dial should not be called when local file is missing")
	}
	if deployCalled {
		t.Fatal("deploySystemdUpdate should not be called when local file is missing")
	}
}

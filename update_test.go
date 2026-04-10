package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zjyl1994/sdup/pkg/sshclient"
)

func TestSystemdUpdateSkipsSSHWhenLocalFileMissing(t *testing.T) {
	origDial := dialSSHSessionFn
	origDeploy := deploySystemdUpdateFn
	origReport := reportUploadStartFn
	defer func() {
		dialSSHSessionFn = origDial
		deploySystemdUpdateFn = origDeploy
		reportUploadStartFn = origReport
	}()

	dialCalled := false
	deployCalled := false
	deployOpts := defaultDeploymentOptions()

	dialSSHSessionFn = func(remoteHost string, sshOptions sshclient.Options) (sshclient.Session, error) {
		dialCalled = true
		return nil, errors.New("unexpected dial")
	}
	deploySystemdUpdateFn = func(session sshclient.Session, localFile, remoteService string, totalSize int64, opts deploymentOptions) error {
		deployCalled = true
		if opts != deployOpts {
			t.Fatalf("deployment options = %+v, want %+v", opts, deployOpts)
		}
		return nil
	}

	err := SystemdUpdate("/tmp/definitely-missing-sdup-binary", "api", "prod", sshCLIOptions{}, deployOpts)
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

func TestSystemdUpdatePrintsLocalSizeBeforeSSH(t *testing.T) {
	origDial := dialSSHSessionFn
	origDeploy := deploySystemdUpdateFn
	origReport := reportUploadStartFn
	defer func() {
		dialSSHSessionFn = origDial
		deploySystemdUpdateFn = origDeploy
		reportUploadStartFn = origReport
	}()

	localFile := filepath.Join(t.TempDir(), "api")
	content := []byte("hello")
	if err := os.WriteFile(localFile, content, 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	reported := false
	deployOpts := deploymentOptions{healthCheckWait: 2}
	reportUploadStartFn = func(totalSize int64) {
		reported = true
		if totalSize != int64(len(content)) {
			t.Fatalf("reported totalSize = %d, want %d", totalSize, len(content))
		}
	}
	dialSSHSessionFn = func(remoteHost string, sshOptions sshclient.Options) (sshclient.Session, error) {
		if !reported {
			t.Fatal("expected upload size to be reported before SSH dial")
		}
		return &fakeRemoteSession{}, nil
	}
	deploySystemdUpdateFn = func(session sshclient.Session, localFile, remoteService string, totalSize int64, opts deploymentOptions) error {
		if totalSize != int64(len(content)) {
			t.Fatalf("totalSize = %d, want %d", totalSize, len(content))
		}
		if opts != deployOpts {
			t.Fatalf("deployment options = %+v, want %+v", opts, deployOpts)
		}
		return nil
	}

	if err := SystemdUpdate(localFile, "api", "prod", sshCLIOptions{}, deployOpts); err != nil {
		t.Fatalf("SystemdUpdate returned error: %v", err)
	}
	if !reported {
		t.Fatal("expected upload size to be reported")
	}
}

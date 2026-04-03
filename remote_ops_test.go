package main

import (
	"bytes"
	"errors"
	"os"
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
		uploadErr:    errors.New("upload failed"),
		mktempOutput: "/tmp/sdup.testdir\n",
	}
	var out bytes.Buffer

	_, err := uploadWithProgressToWriter(session, localFile, &out)
	if !errors.Is(err, session.uploadErr) {
		t.Fatalf("uploadWithProgressToWriter error = %v, want %v", err, session.uploadErr)
	}
	if len(session.runCommands) != 2 {
		t.Fatalf("len(runCommands) = %d, want %d", len(session.runCommands), 2)
	}
	if got := session.runCommands[1]; got != "rm -rf -- '/tmp/sdup.testdir'" {
		t.Fatalf("cleanup command = %q, want %q", got, "rm -rf -- '/tmp/sdup.testdir'")
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
	runCommands  []string
	uploadErr    error
	mktempOutput string
}

func (s *fakeRemoteSession) Run(cmd string) ([]byte, error) {
	s.runCommands = append(s.runCommands, cmd)
	switch {
	case cmd == "mktemp -d -t sdup.XXXXXX":
		return []byte(s.mktempOutput), nil
	case strings.HasPrefix(cmd, "rm -rf -- "):
		return nil, nil
	default:
		return nil, nil
	}
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

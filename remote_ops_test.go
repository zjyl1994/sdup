package main

import "testing"

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

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

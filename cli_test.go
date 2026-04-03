package main

import (
	"flag"
	"testing"
)

func TestCLIParseArgs(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantPort      int
		wantService   string
		wantLocalPath string
		wantRemote    string
	}{
		{
			name:          "attached port",
			args:          []string{"-p2222", "./local", "prod"},
			wantPort:      2222,
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "attached service",
			args:          []string{"-snginx", "./local", "prod"},
			wantPort:      22,
			wantService:   "nginx",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "attached port and service",
			args:          []string{"-p2200", "-sapi", "./local", "prod"},
			wantPort:      2200,
			wantService:   "api",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "standard flag syntax still works",
			args:          []string{"-p", "2201", "-s", "worker", "./local", "prod"},
			wantPort:      2201,
			wantService:   "worker",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "equals syntax still works",
			args:          []string{"-p=2202", "-s=web", "./local", "prod"},
			wantPort:      2202,
			wantService:   "web",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseCLIArgs(tt.args)
			if err != nil {
				t.Fatalf("parseCLIArgs returned error: %v", err)
			}
			if opts.sshPort != tt.wantPort {
				t.Fatalf("sshPort = %d, want %d", opts.sshPort, tt.wantPort)
			}
			if opts.remoteService != tt.wantService {
				t.Fatalf("remoteService = %q, want %q", opts.remoteService, tt.wantService)
			}
			if got := opts.args[0]; got != tt.wantLocalPath {
				t.Fatalf("local_path = %q, want %q", got, tt.wantLocalPath)
			}
			if got := opts.args[1]; got != tt.wantRemote {
				t.Fatalf("remote_host = %q, want %q", got, tt.wantRemote)
			}
		})
	}
}

func TestCLINormalizeAttachedShortFlagValues(t *testing.T) {
	fs := newCLIFlagSetForTest()
	got := normalizeAttachedShortFlagValues(fs, []string{"--", "-p2222", "-sapi"})
	want := []string{"--", "-p2222", "-sapi"}

	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCLIParseArgsHelp(t *testing.T) {
	_, err := parseCLIArgs([]string{"-h"})
	if err != flag.ErrHelp {
		t.Fatalf("parseCLIArgs(-h) error = %v, want %v", err, flag.ErrHelp)
	}
}

func newCLIFlagSetForTest() *flag.FlagSet {
	fs := flag.NewFlagSet("sdup", flag.ContinueOnError)
	var port int
	var service string
	fs.IntVar(&port, "p", 22, "SSH port")
	fs.StringVar(&service, "s", "", "Remote service")
	return fs
}

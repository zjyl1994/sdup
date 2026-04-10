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
		wantPortSet   bool
		wantConfig    string
		wantConfigSet bool
		wantIDs       []string
		wantSSHOpts   []string
		wantIgnoreKH  bool
		wantService   string
		wantWrite     bool
		wantLocalPath string
		wantRemote    string
	}{
		{
			name:          "attached port",
			args:          []string{"-p2222", "./local", "prod"},
			wantPort:      2222,
			wantPortSet:   true,
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "attached service",
			args:          []string{"-snginx", "./local", "prod"},
			wantPort:      22,
			wantPortSet:   false,
			wantService:   "nginx",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "attached port and service",
			args:          []string{"-p2200", "-sapi", "./local", "prod"},
			wantPort:      2200,
			wantPortSet:   true,
			wantService:   "api",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "standard flag syntax still works",
			args:          []string{"-p", "2201", "-s", "worker", "./local", "prod"},
			wantPort:      2201,
			wantPortSet:   true,
			wantService:   "worker",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "equals syntax still works",
			args:          []string{"-p=2202", "-s=web", "./local", "prod"},
			wantPort:      2202,
			wantPortSet:   true,
			wantService:   "web",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "case insensitive ssh flags",
			args:          []string{"-P2203", "-F", "ssh_config", "-I", "~/.ssh/id_demo", "-O", "Port=2204", "./local", "prod"},
			wantPort:      2203,
			wantPortSet:   true,
			wantConfig:    "ssh_config",
			wantConfigSet: true,
			wantIDs:       []string{"~/.ssh/id_demo"},
			wantSSHOpts:   []string{"Port=2204"},
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "ignore known hosts flag after positional args",
			args:          []string{"./local", "prod", "-K"},
			wantPort:      22,
			wantPortSet:   false,
			wantIgnoreKH:  true,
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "flags after positional args",
			args:          []string{"./local", "prod", "-p", "2205", "-s", "api"},
			wantPort:      2205,
			wantPortSet:   true,
			wantService:   "api",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:          "interleaved positional args and case insensitive flags",
			args:          []string{"./local", "-P2206", "prod", "-Sworker", "-F", "ssh_config", "-N7"},
			wantPort:      2206,
			wantPortSet:   true,
			wantConfig:    "ssh_config",
			wantConfigSet: true,
			wantService:   "worker",
			wantLocalPath: "./local",
			wantRemote:    "prod",
		},
		{
			name:        "write config without positional args",
			args:        []string{"-W"},
			wantPort:    22,
			wantPortSet: false,
			wantWrite:   true,
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
			if opts.sshPortSet != tt.wantPortSet {
				t.Fatalf("sshPortSet = %v, want %v", opts.sshPortSet, tt.wantPortSet)
			}
			if opts.sshConfigPath != tt.wantConfig {
				t.Fatalf("sshConfigPath = %q, want %q", opts.sshConfigPath, tt.wantConfig)
			}
			if opts.sshConfigSet != tt.wantConfigSet {
				t.Fatalf("sshConfigSet = %v, want %v", opts.sshConfigSet, tt.wantConfigSet)
			}
			if !equalStringSlices([]string(opts.identityFiles), tt.wantIDs) {
				t.Fatalf("identityFiles = %v, want %v", []string(opts.identityFiles), tt.wantIDs)
			}
			if !equalStringSlices([]string(opts.sshOptions), tt.wantSSHOpts) {
				t.Fatalf("sshOptions = %v, want %v", []string(opts.sshOptions), tt.wantSSHOpts)
			}
			if opts.ignoreKnownHosts != tt.wantIgnoreKH {
				t.Fatalf("ignoreKnownHosts = %v, want %v", opts.ignoreKnownHosts, tt.wantIgnoreKH)
			}
			if opts.remoteService != tt.wantService {
				t.Fatalf("remoteService = %q, want %q", opts.remoteService, tt.wantService)
			}
			if opts.writeConfig != tt.wantWrite {
				t.Fatalf("writeConfig = %v, want %v", opts.writeConfig, tt.wantWrite)
			}
			if tt.wantLocalPath != "" || len(opts.args) > 0 {
				if len(opts.args) < 1 {
					t.Fatalf("missing local_path, want %q", tt.wantLocalPath)
				}
				if got := opts.args[0]; got != tt.wantLocalPath {
					t.Fatalf("local_path = %q, want %q", got, tt.wantLocalPath)
				}
			}
			if tt.wantRemote != "" || len(opts.args) > 1 {
				if len(opts.args) < 2 {
					t.Fatalf("missing remote_host, want %q", tt.wantRemote)
				}
				if got := opts.args[1]; got != tt.wantRemote {
					t.Fatalf("remote_host = %q, want %q", got, tt.wantRemote)
				}
			}
		})
	}
}

func TestCLINormalizeArgs(t *testing.T) {
	fs := newCLIFlagSetForTest()
	got := normalizeCLIArgs(fs, []string{"-P2222", "-Sapi", "--", "-Fconfig"})
	want := []string{"-p", "2222", "-s", "api", "--", "-Fconfig"}

	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCLIReorderArgs(t *testing.T) {
	fs := newCLIFlagSetForTest()
	got := reorderCLIArgs(fs, []string{"./local", "prod", "-P2222", "-Sapi"})
	want := []string{"-p", "2222", "-s", "api", "./local", "prod"}

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

func TestCLIParseArgsTracksExplicitLogLineOverride(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantLogLines    int
		wantLogLinesSet bool
	}{
		{name: "unset", args: []string{"./local", "prod"}, wantLogLines: defaultDeployLogLines, wantLogLinesSet: false},
		{name: "space syntax", args: []string{"-n", "7", "./local", "prod"}, wantLogLines: 7, wantLogLinesSet: true},
		{name: "attached syntax", args: []string{"-N9", "./local", "prod"}, wantLogLines: 9, wantLogLinesSet: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseCLIArgs(tt.args)
			if err != nil {
				t.Fatalf("parseCLIArgs returned error: %v", err)
			}
			if opts.deployment.logLines != tt.wantLogLines {
				t.Fatalf("logLines = %d, want %d", opts.deployment.logLines, tt.wantLogLines)
			}
			if opts.deployment.logLinesSet != tt.wantLogLinesSet {
				t.Fatalf("logLinesSet = %v, want %v", opts.deployment.logLinesSet, tt.wantLogLinesSet)
			}
		})
	}
}

func TestCLIParseArgsTracksExplicitPortOverride(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantSSHPortSet bool
	}{
		{
			name:           "unset",
			args:           []string{"./local", "prod"},
			wantSSHPortSet: false,
		},
		{
			name:           "space syntax",
			args:           []string{"-p", "2201", "./local", "prod"},
			wantSSHPortSet: true,
		},
		{
			name:           "attached syntax",
			args:           []string{"-p2201", "./local", "prod"},
			wantSSHPortSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseCLIArgs(tt.args)
			if err != nil {
				t.Fatalf("parseCLIArgs returned error: %v", err)
			}
			if opts.sshPortSet != tt.wantSSHPortSet {
				t.Fatalf("sshPortSet = %v, want %v", opts.sshPortSet, tt.wantSSHPortSet)
			}
		})
	}
}

func newCLIFlagSetForTest() *flag.FlagSet {
	fs := flag.NewFlagSet("sdup", flag.ContinueOnError)
	var port int
	var config string
	var ids stringSliceFlag
	var sshOptions stringSliceFlag
	var ignoreKnownHosts bool
	var service string
	var logLines int
	var writeConfig bool
	fs.IntVar(&port, "p", 22, "SSH port")
	fs.StringVar(&config, "f", "", "SSH config file")
	fs.Var(&ids, "i", "SSH identity file")
	fs.Var(&sshOptions, "o", "SSH option in key=value form")
	fs.BoolVar(&ignoreKnownHosts, "k", false, "Ignore SSH known_hosts host key verification")
	fs.StringVar(&service, "s", "", "Remote service")
	fs.IntVar(&logLines, "n", defaultDeployLogLines, "Recent journal lines to print after deploy (0 disables)")
	fs.BoolVar(&writeConfig, "w", false, "Write repo-local .sdup.toml from current arguments and exit")
	return fs
}

func equalStringSlices(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

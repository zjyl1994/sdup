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
			if got := intPointerOr(opts.ssh.port, 22); got != tt.wantPort {
				t.Fatalf("sshPort = %d, want %d", got, tt.wantPort)
			}
			if got := opts.ssh.port != nil; got != tt.wantPortSet {
				t.Fatalf("sshPortSet = %v, want %v", got, tt.wantPortSet)
			}
			if got := stringPointerValue(opts.ssh.configPath); got != tt.wantConfig {
				t.Fatalf("sshConfigPath = %q, want %q", got, tt.wantConfig)
			}
			if got := opts.ssh.configPath != nil; got != tt.wantConfigSet {
				t.Fatalf("sshConfigSet = %v, want %v", got, tt.wantConfigSet)
			}
			if !equalStringSlices(opts.ssh.identityFiles, tt.wantIDs) {
				t.Fatalf("identityFiles = %v, want %v", opts.ssh.identityFiles, tt.wantIDs)
			}
			if !equalStringSlices(opts.ssh.rawOptions, tt.wantSSHOpts) {
				t.Fatalf("sshOptions = %v, want %v", opts.ssh.rawOptions, tt.wantSSHOpts)
			}
			if got := boolPointerValue(opts.ssh.ignoreKnownHosts); got != tt.wantIgnoreKH {
				t.Fatalf("ignoreKnownHosts = %v, want %v", got, tt.wantIgnoreKH)
			}
			if opts.remoteService != tt.wantService {
				t.Fatalf("remoteService = %q, want %q", opts.remoteService, tt.wantService)
			}
			if opts.writeConfig != tt.wantWrite {
				t.Fatalf("writeConfig = %v, want %v", opts.writeConfig, tt.wantWrite)
			}
			if tt.wantLocalPath != "" || opts.localPath != "" {
				if got := opts.localPath; got != tt.wantLocalPath {
					t.Fatalf("local_path = %q, want %q", got, tt.wantLocalPath)
				}
			}
			if tt.wantRemote != "" || opts.remoteHost != "" {
				if got := opts.remoteHost; got != tt.wantRemote {
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
			if got := intPointerOr(opts.deployment.logLines, defaultDeployLogLines); got != tt.wantLogLines {
				t.Fatalf("logLines = %d, want %d", got, tt.wantLogLines)
			}
			if got := opts.deployment.logLines != nil; got != tt.wantLogLinesSet {
				t.Fatalf("logLinesSet = %v, want %v", got, tt.wantLogLinesSet)
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
			if got := opts.ssh.port != nil; got != tt.wantSSHPortSet {
				t.Fatalf("sshPortSet = %v, want %v", got, tt.wantSSHPortSet)
			}
		})
	}
}

func TestCLIParseArgsTracksExplicitKnownHostsOverride(t *testing.T) {
	tests := []struct {
		name                    string
		args                    []string
		wantIgnoreKnownHosts    bool
		wantIgnoreKnownHostsSet bool
	}{
		{
			name:                    "unset",
			args:                    []string{"./local", "prod"},
			wantIgnoreKnownHosts:    false,
			wantIgnoreKnownHostsSet: false,
		},
		{
			name:                    "true",
			args:                    []string{"-k", "./local", "prod"},
			wantIgnoreKnownHosts:    true,
			wantIgnoreKnownHostsSet: true,
		},
		{
			name:                    "explicit false",
			args:                    []string{"-k=false", "./local", "prod"},
			wantIgnoreKnownHosts:    false,
			wantIgnoreKnownHostsSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseCLIArgs(tt.args)
			if err != nil {
				t.Fatalf("parseCLIArgs returned error: %v", err)
			}
			if got := boolPointerValue(opts.ssh.ignoreKnownHosts); got != tt.wantIgnoreKnownHosts {
				t.Fatalf("ignoreKnownHosts = %v, want %v", got, tt.wantIgnoreKnownHosts)
			}
			if got := opts.ssh.ignoreKnownHosts != nil; got != tt.wantIgnoreKnownHostsSet {
				t.Fatalf("ignoreKnownHostsSet = %v, want %v", got, tt.wantIgnoreKnownHostsSet)
			}
		})
	}
}

func TestCLIParseArgsRejectsInvalidExplicitPort(t *testing.T) {
	_, err := parseCLIArgs([]string{"-p", "70000", "./local", "prod"})
	if err == nil {
		t.Fatal("parseCLIArgs returned nil error")
	}
	if got := err.Error(); got != "port must be between 1 and 65535" {
		t.Fatalf("parseCLIArgs error = %q, want %q", got, "port must be between 1 and 65535")
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

func intPointerOr(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func boolPointerValue(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}

func stringPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

package sshclient

import "testing"

func TestSSHTargetParseUserHostPort(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		wantUser string
		wantHost string
		wantPort int
	}{
		{
			name:     "user host and port",
			spec:     "root@example.com:2222",
			wantUser: "root",
			wantHost: "example.com",
			wantPort: 2222,
		},
		{
			name:     "host only",
			spec:     "example.com",
			wantUser: "",
			wantHost: "example.com",
			wantPort: 0,
		},
		{
			name:     "ipv6 with port",
			spec:     "deploy@[2001:db8::1]:2200",
			wantUser: "deploy",
			wantHost: "2001:db8::1",
			wantPort: 2200,
		},
		{
			name:     "raw ipv6 without port",
			spec:     "2001:db8::1",
			wantUser: "",
			wantHost: "2001:db8::1",
			wantPort: 0,
		},
		{
			name:     "invalid port keeps host",
			spec:     "root@example.com:not-a-port",
			wantUser: "root",
			wantHost: "example.com:not-a-port",
			wantPort: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotHost, gotPort, err := parseUserHostPort(tt.spec)
			if err != nil {
				t.Fatalf("parseUserHostPort returned error: %v", err)
			}
			if gotUser != tt.wantUser {
				t.Fatalf("user = %q, want %q", gotUser, tt.wantUser)
			}
			if gotHost != tt.wantHost {
				t.Fatalf("host = %q, want %q", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Fatalf("port = %d, want %d", gotPort, tt.wantPort)
			}
		})
	}
}

func TestSSHTargetParseUserHostPortRejectsOutOfRangePort(t *testing.T) {
	_, _, _, err := parseUserHostPort("example.com:70000")
	if err == nil {
		t.Fatal("parseUserHostPort returned nil error")
	}
	if got := err.Error(); got != "port must be between 1 and 65535" {
		t.Fatalf("parseUserHostPort error = %q, want %q", got, "port must be between 1 and 65535")
	}
}

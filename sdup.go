package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	sshconfig "github.com/kevinburke/ssh_config"
	"github.com/melbahja/goph"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// HostConfig holds resolved SSH connection parameters
// simple English comments as requested
type HostConfig struct {
	User          string
	Hostname      string
	Port          int
	IdentityFiles []string
}

// resolveSSHConfig tries to use local ssh config to fill host params
func resolveSSHConfig(alias string, fallbackPort int) (*HostConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cfg := &HostConfig{
		User:          os.Getenv("USER"),
		Hostname:      alias,
		Port:          fallbackPort,
		IdentityFiles: []string{},
	}

	// read ~/.ssh/config if exists
	sshConfPath := filepath.Join(homeDir, ".ssh", "config")
	if f, err := os.Open(sshConfPath); err == nil {
		defer f.Close()
		// parse using kevinburke/ssh_config
		parsed, perr := sshconfig.Decode(bufio.NewReader(f))
		if perr == nil {
			// try to match host alias
			host := alias
			// HostName may override real hostname
			if hn, _ := parsed.Get(host, "HostName"); hn != "" {
				cfg.Hostname = hn
			}
			if u, _ := parsed.Get(host, "User"); u != "" {
				cfg.User = u
			}
			if p, _ := parsed.Get(host, "Port"); p != "" {
				// ignore error, fallback to previous value
				if ip, convErr := parseInt(p); convErr == nil {
					cfg.Port = ip
				}
			}
			// collect identity files (can include multiple)
			if ids, _ := parsed.GetAll(host, "IdentityFile"); len(ids) > 0 {
				for _, id := range ids {
					// expand ~ to home
					id = strings.Replace(id, "~", homeDir, 1)
					cfg.IdentityFiles = append(cfg.IdentityFiles, id)
				}
			}
		}
	}

	// default identity files if not present: scan ~/.ssh
	if len(cfg.IdentityFiles) == 0 {
		cfg.IdentityFiles = findDefaultIdentityFiles(homeDir)
		// still empty: fallback to common names
		if len(cfg.IdentityFiles) == 0 {
			cfg.IdentityFiles = []string{
				filepath.Join(homeDir, ".ssh", "id_ed25519"),
				filepath.Join(homeDir, ".ssh", "id_rsa"),
				filepath.Join(homeDir, ".ssh", "id_ecdsa"),
				filepath.Join(homeDir, ".ssh", "id_dsa"),
			}
		}
	}

	// default user if empty
	if cfg.User == "" {
		cfg.User = os.Getenv("USER")
	}

	return cfg, nil
}

// parseInt converts string to int safely
func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// chooseAuth tries agent first then identity files
func chooseAuth(ids []string) (goph.Auth, error) {
	// prefer ssh-agent if available
	if os.Getenv("SSH_AUTH_SOCK") != "" {
		auth, err := goph.UseAgent()
		if err == nil {
			return auth, nil
		}
	}
	// try identity files without passphrase
	passphrase := getKeyPassphrase()
	for _, id := range ids {
		if fileExists(id) {
			auth, err := goph.Key(id, passphrase)
			if err == nil {
				return auth, nil
			}
		}
	}
	// fallback to password from env if provided
	if passAuth, ok := getPasswordAuth(); ok {
		return passAuth, nil
	}
	return nil, errors.New("no valid SSH auth method found")
}

// fileExists checks if file exists
func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

// findDefaultIdentityFiles scans ~/.ssh for typical private keys
func findDefaultIdentityFiles(homeDir string) []string {
	sshDir := filepath.Join(homeDir, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	add := func(set map[string]struct{}, p string) {
		if fileExists(p) {
			set[p] = struct{}{}
		}
	}
	keys := make(map[string]struct{})
	// common names
	add(keys, filepath.Join(sshDir, "id_ed25519"))
	add(keys, filepath.Join(sshDir, "id_rsa"))
	add(keys, filepath.Join(sshDir, "id_ecdsa"))
	add(keys, filepath.Join(sshDir, "id_dsa"))
	// scan id_* files excluding .pub
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub") {
			add(keys, filepath.Join(sshDir, name))
		}
	}
	// convert to slice
	out := make([]string, 0, len(keys))
	for p := range keys {
		out = append(out, p)
	}
	return out
}

// getKeyPassphrase returns passphrase from env if provided
func getKeyPassphrase() string {
	return os.Getenv("SDUP_SSH_KEY_PASSPHRASE")
}

// getPasswordAuth returns password auth from env if set
func getPasswordAuth() (goph.Auth, bool) {
	pwd := os.Getenv("SDUP_SSH_PASSWORD")
	if strings.TrimSpace(pwd) != "" {
		return goph.Password(pwd), true
	}
	return nil, false
}

// isAuthFailure checks common ssh authentication failure messages
func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain") ||
		strings.Contains(msg, "handshake failed")
}

// fetchExecStartPath runs systemctl show and extracts ExecStart path
func fetchExecStartPath(client *goph.Client, unit string) (string, error) {
	cmd := fmt.Sprintf("systemctl show %s -p ExecStart", unit)
	out, err := client.Run(cmd)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(out))
	// expected like: ExecStart={ path=/usr/bin/xxx ; argv[]=... }
	if !strings.HasPrefix(line, "ExecStart=") {
		return "", errors.New("unexpected systemctl output")
	}
	val := strings.TrimPrefix(line, "ExecStart=")
	// try structured path=...
	re := regexp.MustCompile(`path=([^ ;]+)`) // get path value
	if m := re.FindStringSubmatch(val); len(m) == 2 {
		return m[1], nil
	}
	// fallback: take first token if it looks like an absolute path
	tokens := strings.Fields(val)
	if len(tokens) > 0 && strings.HasPrefix(tokens[0], "/") {
		return tokens[0], nil
	}
	return "", errors.New("ExecStart path not found")
}

// uploadWithProgress uploads local file to remote temp directory using sftp
// returns remote temporary file path
func uploadWithProgress(client *goph.Client, localPath string) (string, error) {
	// ensure local file exists
	lf, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer lf.Close()

	st, err := lf.Stat()
	if err != nil {
		return "", err
	}
	total := st.Size()

	// create sftp client
	s, err := client.NewSftp(sftp.MaxPacket(1 << 15))
	if err != nil {
		return "", err
	}
	defer s.Close()

	// create remote temp dir and file
	// use mktemp pattern for unique name
	out, err := client.Run("mktemp -d -t sdup.XXXXXX")
	if err != nil {
		return "", err
	}
	rdir := strings.TrimSpace(string(out))
	rfile := filepath.Join(rdir, filepath.Base(localPath))

	rf, err := s.Create(rfile)
	if err != nil {
		return "", err
	}
	defer rf.Close()

	// copy with progress
	buf := make([]byte, 128*1024)
	var sent int64
	for {
		n, rerr := lf.Read(buf)
		if n > 0 {
			wn, werr := rf.Write(buf[:n])
			if werr != nil {
				return "", werr
			}
			if wn != n {
				return "", io.ErrShortWrite
			}
			sent += int64(n)
			// simple progress to stdout
			pct := float64(sent) / float64(total) * 100
			fmt.Printf("Uploading: %.1f%%\r", pct)
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return "", rerr
		}
	}
	fmt.Printf("\nUpload complete: %s -> %s\n", localPath, rfile)

	return rfile, nil
}

// SystemdUpdate connects over SSH and prints ExecStart path
func SystemdUpdate(localFile, remoteService, remoteHost string, remotePort int) error {
	// parse user and port from host like user@host:port
	userOverride, hostAlias, portOverride := parseUserHostPort(remoteHost)

	// resolve SSH config from system using alias; use CLI port as fallback
	cfg, err := resolveSSHConfig(hostAlias, remotePort)
	if err != nil {
		return err
	}

	// override user per precedence: CLI (none) > host string > ssh_config
	if userOverride != "" {
		cfg.User = userOverride
	}
	// override port per precedence: CLI > host string > ssh_config
	if remotePort > 0 {
		cfg.Port = remotePort
	} else if portOverride > 0 {
		cfg.Port = portOverride
	}

	// choose auth
	auth, err := chooseAuth(cfg.IdentityFiles)
	if err != nil {
		return err
	}

	// connect via goph with insecure host key (improve later with known_hosts)
	client, err := goph.NewConn(&goph.Config{
		User: cfg.User,
		Addr: cfg.Hostname,
		Port: uint(cfg.Port),
		Auth: auth,
		// NOTE: use insecure hostkey for now; consider known_hosts
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		// Retry with password auth if authentication failed and password is set
		if isAuthFailure(err) {
			if passAuth, ok := getPasswordAuth(); ok {
				client, err = goph.NewConn(&goph.Config{
					User:     cfg.User,
					Addr:     cfg.Hostname,
					Port:     uint(cfg.Port),
					Auth:     passAuth,
					Callback: ssh.InsecureIgnoreHostKey(),
				})
			}
		}
		if err != nil {
			return err
		}
	}
	defer client.Close()

	// fetch ExecStart path
	execPath, err := fetchExecStartPath(client, remoteService)
	if err != nil {
		return err
	}

	// print result (English, minimal)
	fmt.Printf("ExecStart path: %s\n", execPath)

	// upload local file to remote temp dir
	tmpRemoteFile, err := uploadWithProgress(client, localFile)
	if err != nil {
		return err
	}

	// prepare install command: preserve permissions and atomic replace
	// use root paths and need sudo if not root
	installer := fmt.Sprintf("sudo install -m 0755 -T %s %s", tmpRemoteFile, execPath)
	out, err := client.Run(installer)
	if err != nil {
		return fmt.Errorf("install failed: %v, output: %s", err, string(out))
	}

	// restart service with minimal output
	restartCmd := fmt.Sprintf("sudo systemctl restart %s", remoteService)
	out, err = client.Run(restartCmd)
	if err != nil {
		return fmt.Errorf("restart failed: %v, output: %s", err, string(out))
	}
	fmt.Printf("Service restarted: %s\n", remoteService)

	// TODO: use localFile and execPath for further update logic if needed
	return nil
}

// parseUserHostPort splits "user@host:port" and returns user, host, port
// for ipv6 with port, use "user@[2001:db8::1]:2222"
func parseUserHostPort(spec string) (string, string, int) {
	spec = strings.TrimSpace(spec)
	// extract user if present
	user := ""
	hostport := spec
	if at := strings.LastIndex(spec, "@"); at != -1 {
		user = strings.TrimSpace(spec[:at])
		hostport = spec[at+1:]
	}

	host := strings.TrimSpace(hostport)
	port := 0

	if strings.HasPrefix(hostport, "[") {
		// bracketed ipv6: [addr]:port?
		end := strings.Index(hostport, "]")
		if end != -1 {
			addr := hostport[1:end]
			host = addr
			rest := hostport[end+1:]
			if strings.HasPrefix(rest, ":") {
				pstr := strings.TrimSpace(rest[1:])
				if p, err := parseInt(pstr); err == nil {
					port = p
				}
			}
		}
	} else {
		// user@host:port or host:port (ipv6 without brackets not supported here)
		if idx := strings.LastIndex(hostport, ":"); idx != -1 {
			pstr := hostport[idx+1:]
			if p, err := parseInt(pstr); err == nil {
				port = p
				host = hostport[:idx]
			}
		}
	}

	return strings.TrimSpace(user), strings.TrimSpace(host), port
}

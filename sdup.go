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
	User           string
	Hostname       string
	Port           int
	IdentityFiles  []string
	IdentitiesOnly bool
	AgentSocket    string
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
			if ioVal, _ := parsed.Get(host, "IdentitiesOnly"); parseSSHBool(ioVal) {
				cfg.IdentitiesOnly = true
			}
			if ia, _ := parsed.Get(host, "IdentityAgent"); strings.TrimSpace(ia) != "" {
				ia = strings.TrimSpace(ia)
				if strings.EqualFold(ia, "none") {
					cfg.AgentSocket = "none"
				} else if strings.HasPrefix(ia, "~") {
					cfg.AgentSocket = strings.Replace(ia, "~", homeDir, 1)
				} else if ia != "SSH_AUTH_SOCK" {
					cfg.AgentSocket = ia
				}
			}
		}
	}

	defaultIDs := findDefaultIdentityFiles(homeDir)
	if len(defaultIDs) == 0 {
		defaultIDs = []string{
			filepath.Join(homeDir, ".ssh", "id_rsa"),
			filepath.Join(homeDir, ".ssh", "id_ecdsa"),
			filepath.Join(homeDir, ".ssh", "id_ecdsa_sk"),
			filepath.Join(homeDir, ".ssh", "id_ed25519"),
			filepath.Join(homeDir, ".ssh", "id_ed25519_sk"),
			filepath.Join(homeDir, ".ssh", "id_xmss"),
			filepath.Join(homeDir, ".ssh", "id_dsa"),
		}
	}
	cfg.IdentityFiles = mergeIdentityFiles(cfg.IdentityFiles, defaultIDs)

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

// buildAuthChain constructs ordered auth methods: keys -> agent -> password
func buildAuthChain(cfg *HostConfig) []goph.Auth {
	chain := []goph.Auth{}
	// key files first
	passphrase := getKeyPassphrase()
	for _, id := range cfg.IdentityFiles {
		if fileExists(id) {
			if auth, err := goph.Key(id, passphrase); err == nil {
				chain = append(chain, auth)
			}
		}
	}
	// then agent if available and usable
	if !cfg.IdentitiesOnly && cfg.AgentSocket != "none" {
		sock := cfg.AgentSocket
		if sock == "" {
			sock = os.Getenv("SSH_AUTH_SOCK")
		}
		if strings.TrimSpace(sock) != "" {
			if auth, err := useAgentWithSocket(sock); err == nil {
				chain = append(chain, auth)
			}
		}
	}
	// finally password if provided
	if passAuth, ok := getPasswordAuth(); ok {
		chain = append(chain, passAuth)
	}
	return chain
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
	candidates := []string{
		"id_rsa",
		"id_ecdsa",
		"id_ecdsa_sk",
		"id_ed25519",
		"id_ed25519_sk",
		"id_xmss",
		"id_dsa",
	}
	out := make([]string, 0, len(candidates))
	for _, name := range candidates {
		p := filepath.Join(sshDir, name)
		if fileExists(p) {
			out = append(out, p)
		}
	}
	return out
}

func parseSSHBool(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "yes" || v == "true" || v == "on" || v == "1"
}

func mergeIdentityFiles(primary []string, secondary []string) []string {
	out := make([]string, 0, len(primary)+len(secondary))
	seen := map[string]struct{}{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if strings.EqualFold(id, "none") {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range primary {
		add(id)
	}
	for _, id := range secondary {
		add(id)
	}
	return out
}

func useAgentWithSocket(sock string) (goph.Auth, error) {
	origin, hadOrigin := os.LookupEnv("SSH_AUTH_SOCK")
	if err := os.Setenv("SSH_AUTH_SOCK", sock); err != nil {
		return nil, err
	}
	auth, err := goph.UseAgent()
	if hadOrigin {
		_ = os.Setenv("SSH_AUTH_SOCK", origin)
	} else {
		_ = os.Unsetenv("SSH_AUTH_SOCK")
	}
	return auth, err
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

// composeUpdateCommand builds a single bash command to install, restart, and cleanup
func composeUpdateCommand(execPath, service, tmpFile string) string {
	dir := filepath.Dir(tmpFile)
	// always cleanup on EXIT; install and restart run with set -e
	return fmt.Sprintf(
		"trap 'rm -f %s; rmdir %s 2>/dev/null || true' EXIT; set -e; sudo install -m 0755 -T %s %s && sudo systemctl restart %s",
		tmpFile, dir, tmpFile, execPath, service,
	)
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

	// build auth fallback chain and connect by trying each
	authChain := buildAuthChain(cfg)
	if len(authChain) == 0 {
		return errors.New("no valid SSH auth method found")
	}

	var client *goph.Client
	var connErr error
	for _, auth := range authChain {
		client, connErr = goph.NewConn(&goph.Config{
			User:     cfg.User,
			Addr:     cfg.Hostname,
			Port:     uint(cfg.Port),
			Auth:     auth,
			Callback: ssh.InsecureIgnoreHostKey(),
		})
		if connErr == nil {
			break
		}
		// if it's an auth failure, continue to next method; otherwise abort
		if !isAuthFailure(connErr) {
			return connErr
		}
	}
	if connErr != nil {
		return connErr
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

	// run install + restart + cleanup in a single remote command to reduce network issues
	combined := composeUpdateCommand(execPath, remoteService, tmpRemoteFile)
	out, err := client.Run(combined)
	if err != nil {
		return fmt.Errorf("update failed: %v, output: %s", err, string(out))
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

package sshclient

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxPort = 65535

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func ValidatePort(port int) error {
	if port < 1 || port > maxPort {
		return fmt.Errorf("port must be between 1 and %d", maxPort)
	}
	return nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

func expandHomePath(path string, homeDir string) string {
	path = strings.TrimSpace(path)
	switch {
	case path == "~":
		return homeDir
	case strings.HasPrefix(path, "~/"):
		return filepath.Join(homeDir, path[2:])
	default:
		return path
	}
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

func validateLocalFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("local file not found: %s", path)
		}
		return fmt.Errorf("stat local file %q: %w", path, err)
	}
	if st.IsDir() {
		return fmt.Errorf("local path is a directory: %s", path)
	}
	return nil
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

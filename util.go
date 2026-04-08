package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func expandHomePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "~") {
		return path, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch {
	case path == "~":
		return homeDir, nil
	case strings.HasPrefix(path, "~/"):
		return filepath.Join(homeDir, path[2:]), nil
	default:
		return path, nil
	}
}

package main

import (
	"fmt"
	"os"
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

package main

import (
	"os"
	"path/filepath"
)

func main() {
	opts, err := parseCLIArgs(os.Args[1:])
	if err != nil {
		exitWithCLIError(err)
	}

	if opts.remoteService == "" {
		opts.remoteService = filepath.Base(opts.args[0])
	}

	if err := SystemdUpdate(opts.args[0], opts.remoteService, opts.args[1], opts.sshPort); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

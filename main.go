package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}

	opts, err := parseCLIArgs(os.Args[1:])
	if err != nil {
		exitWithCLIError(err)
	}

	opts, repoCtx, err := resolveInvocationOptions(opts, cwd)
	if err != nil {
		exitWithCLIError(err)
	}

	if opts.writeConfig {
		if err := writeRepoConfig(repoCtx.configPath, repoCtx.rootDir, cwd, opts); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		if err := ensureRepoGitignoreEntry(repoCtx.rootDir); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		fmt.Printf("Wrote %s and updated %s\n", repoCtx.configPath, filepath.Join(repoCtx.rootDir, ".gitignore"))
		return
	}

	if err := SystemdUpdate(opts.args[0], opts.remoteService, opts.args[1], buildSSHCLIOptions(opts), buildDeploymentOptions(opts)); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

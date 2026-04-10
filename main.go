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

	cli, err := parseCLIArgs(os.Args[1:])
	if err != nil {
		exitWithCLIError(err)
	}

	inv, repoCtx, err := resolveInvocationOptions(cli, cwd)
	if err != nil {
		exitWithCLIError(err)
	}

	if inv.writeConfig {
		if err := writeRepoConfig(repoCtx.configPath, repoCtx.rootDir, cwd, inv); err != nil {
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

	if err := SystemdUpdate(inv.localPath, inv.remoteService, inv.remoteHost, buildSSHOptions(inv), inv.deployment); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

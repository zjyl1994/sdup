package main

import "github.com/zjyl1994/sdup/pkg/sshclient"

type sshCLIOptions = sshclient.Options

func buildSSHOptions(inv resolvedInvocation) sshCLIOptions {
	sshOptions := sshCLIOptions{
		ConfigPath:       inv.ssh.configPath,
		IdentityFiles:    cloneStrings(inv.ssh.identityFiles),
		RawOptions:       cloneStrings(inv.ssh.rawOptions),
		IgnoreKnownHosts: inv.ssh.ignoreKnownHosts,
	}
	if inv.ssh.port != nil {
		sshOptions.Port = intPtr(*inv.ssh.port)
	}
	return sshOptions
}

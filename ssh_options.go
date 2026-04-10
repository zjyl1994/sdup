package main

import "github.com/zjyl1994/sdup/pkg/sshclient"

func buildSSHOptions(inv resolvedInvocation) sshclient.Options {
	sshOptions := sshclient.Options{
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

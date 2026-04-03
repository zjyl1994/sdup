package main

import "github.com/zjyl1994/sdup/pkg/sshclient"

type sshCLIOptions = sshclient.Options

func buildSSHCLIOptions(opts cliOptions) sshCLIOptions {
	sshOptions := sshCLIOptions{
		ConfigPath:       opts.sshConfigPath,
		IdentityFiles:    append([]string(nil), opts.identityFiles...),
		RawOptions:       append([]string(nil), opts.sshOptions...),
		IgnoreKnownHosts: opts.ignoreKnownHosts,
	}
	if opts.sshPortSet {
		sshOptions.Port = &opts.sshPort
	}
	return sshOptions
}

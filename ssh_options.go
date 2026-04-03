package main

import "github.com/zjyl1994/sdup/pkg/sshclient"

type sshCLIOptions = sshclient.Options

func buildSSHCLIOptions(opts cliOptions) sshCLIOptions {
	sshOptions := sshCLIOptions{
		ConfigPath:    opts.sshConfigPath,
		ConfigPathSet: opts.sshConfigSet,
		IdentityFiles: append([]string(nil), opts.identityFiles...),
		RawOptions:    append([]string(nil), opts.sshOptions...),
	}
	if opts.sshPortSet {
		sshOptions.Port = &opts.sshPort
	}
	return sshOptions
}

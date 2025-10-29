package main

import (
	"flag"
	"os"
	"path/filepath"
)

func main() {
	var sshPort int
	var remoteService string
	flag.IntVar(&sshPort, "p", 22, "SSH port")
	flag.StringVar(&remoteService, "s", "", "Remote service")
	flag.Parse()
	if flag.NArg() != 2 {
		os.Stderr.WriteString("Usage: sdup -p <port> -s <service> <local_path> <remote_host>\n")
		os.Exit(2)
	}
	args := flag.Args()

	if remoteService == "" {
		remoteService = filepath.Base(args[0])
	}

	err := SystemdUpdate(args[0], remoteService, args[1], sshPort)
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

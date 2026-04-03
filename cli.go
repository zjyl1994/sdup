package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usageText = "Usage: sdup [-p <port>|-p<port>] [-s <service>|-s<service>] <local_path> <remote_host>\n"

type cliOptions struct {
	sshPort       int
	remoteService string
	args          []string
}

func parseCLIArgs(args []string) (cliOptions, error) {
	var opts cliOptions

	fs := flag.NewFlagSet("sdup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.IntVar(&opts.sshPort, "p", 22, "SSH port")
	fs.StringVar(&opts.remoteService, "s", "", "Remote service")

	if err := fs.Parse(normalizeAttachedShortFlagValues(fs, args)); err != nil {
		return cliOptions{}, err
	}
	if fs.NArg() != 2 {
		return cliOptions{}, fmt.Errorf("expected 2 positional arguments, got %d", fs.NArg())
	}

	opts.args = fs.Args()
	return opts, nil
}

func normalizeAttachedShortFlagValues(fs *flag.FlagSet, args []string) []string {
	valueFlags := shortValueFlags(fs)
	normalized := make([]string, 0, len(args))

	for i, arg := range args {
		if arg == "--" {
			normalized = append(normalized, args[i:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || len(arg) < 3 {
			normalized = append(normalized, arg)
			continue
		}

		flagName, value, ok := splitAttachedShortFlagValue(arg, valueFlags)
		if !ok {
			normalized = append(normalized, arg)
			continue
		}

		normalized = append(normalized, "-"+flagName, value)
	}

	return normalized
}

func shortValueFlags(fs *flag.FlagSet) []string {
	valueFlags := []string{}
	fs.VisitAll(func(f *flag.Flag) {
		if len(f.Name) != 1 {
			return
		}
		if isBoolFlag(f) {
			return
		}
		valueFlags = append(valueFlags, f.Name)
	})
	return valueFlags
}

func splitAttachedShortFlagValue(arg string, flagNames []string) (string, string, bool) {
	for _, name := range flagNames {
		prefix := "-" + name
		if !strings.HasPrefix(arg, prefix) {
			continue
		}

		value := strings.TrimPrefix(arg, prefix)
		if value == "" || strings.HasPrefix(value, "=") {
			return "", "", false
		}
		return name, value, true
	}
	return "", "", false
}

func isBoolFlag(f *flag.Flag) bool {
	type boolFlag interface {
		IsBoolFlag() bool
	}

	bf, ok := f.Value.(boolFlag)
	return ok && bf.IsBoolFlag()
}

func isUsageError(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(err.Error(), "expected 2 positional arguments")
}

func exitWithCLIError(err error) {
	if err == flag.ErrHelp {
		printUsage(os.Stdout)
		os.Exit(0)
	}

	printUsage(os.Stderr)
	if !isUsageError(err) {
		os.Stderr.WriteString(err.Error() + "\n")
	}
	os.Exit(2)
}

func printUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

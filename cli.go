package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usageText = "Usage: sdup [flags] <local_path> <remote_host>\nFlags are case-insensitive and may appear before or after positional args: -p/-P <port>, -s <service>, -i <identity>, -o <key=value>, -f/-F <config>, -k/-K (ignore known_hosts)\n"

type cliOptions struct {
	sshPort          int
	sshPortSet       bool
	sshConfigPath    string
	sshConfigSet     bool
	identityFiles    stringSliceFlag
	sshOptions       stringSliceFlag
	ignoreKnownHosts bool
	remoteService    string
	args             []string
}

func parseCLIArgs(args []string) (cliOptions, error) {
	var opts cliOptions

	fs := flag.NewFlagSet("sdup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.IntVar(&opts.sshPort, "p", 22, "SSH port")
	fs.StringVar(&opts.sshConfigPath, "f", "", "SSH config file")
	fs.Var(&opts.identityFiles, "i", "SSH identity file")
	fs.Var(&opts.sshOptions, "o", "SSH option in key=value form")
	fs.BoolVar(&opts.ignoreKnownHosts, "k", false, "Ignore SSH known_hosts host key verification")
	fs.StringVar(&opts.remoteService, "s", "", "Remote service")

	if err := fs.Parse(reorderCLIArgs(fs, args)); err != nil {
		return cliOptions{}, err
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "p":
			opts.sshPortSet = true
		case "f":
			opts.sshConfigSet = true
		}
	})
	if fs.NArg() != 2 {
		return cliOptions{}, fmt.Errorf("expected 2 positional arguments, got %d", fs.NArg())
	}

	opts.args = fs.Args()
	return opts, nil
}

func reorderCLIArgs(fs *flag.FlagSet, args []string) []string {
	normalized := normalizeCLIArgs(fs, args)
	reordered := make([]string, 0, len(normalized))
	positionals := make([]string, 0, len(normalized))

	for i := 0; i < len(normalized); i++ {
		arg := normalized[i]
		if arg == "--" {
			positionals = append(positionals, normalized[i+1:]...)
			break
		}

		isFlag, expectsValue, hasInlineValue := classifyCLIArg(fs, arg)
		if isFlag {
			reordered = append(reordered, arg)
			if expectsValue && !hasInlineValue && i+1 < len(normalized) {
				i++
				reordered = append(reordered, normalized[i])
			}
			continue
		}

		if strings.HasPrefix(arg, "-") && arg != "-" {
			reordered = append(reordered, arg)
			continue
		}

		positionals = append(positionals, arg)
	}

	return append(reordered, positionals...)
}

func normalizeCLIArgs(fs *flag.FlagSet, args []string) []string {
	valueFlags := shortValueFlags(fs)
	normalized := make([]string, 0, len(args))

	for i, arg := range args {
		if arg == "--" {
			normalized = append(normalized, args[i:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || len(arg) < 2 {
			normalized = append(normalized, arg)
			continue
		}

		arg = normalizeShortFlagName(arg)
		if len(arg) < 3 {
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

func classifyCLIArg(fs *flag.FlagSet, arg string) (bool, bool, bool) {
	switch arg {
	case "-h", "-help", "--help":
		return true, false, false
	}

	if !strings.HasPrefix(arg, "-") || arg == "-" {
		return false, false, false
	}

	name := strings.TrimLeft(arg, "-")
	hasInlineValue := false
	if idx := strings.Index(name, "="); idx >= 0 {
		name = name[:idx]
		hasInlineValue = true
	}

	f := fs.Lookup(name)
	if f == nil {
		return false, false, false
	}

	return true, !isBoolFlag(f), hasInlineValue
}

func normalizeShortFlagName(arg string) string {
	if len(arg) < 2 || !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
		return arg
	}
	return "-" + strings.ToLower(arg[1:2]) + arg[2:]
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

type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

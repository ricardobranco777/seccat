// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/pflag"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := pflag.NewFlagSet("seccat", pflag.ContinueOnError)
	fs.SetOutput(stderr)
	toJSON := fs.BoolP("json", "j", false, "convert text written by seccat back to profile JSON")
	caps := fs.StringP("caps", "c", "", "the `SET` of capabilities the container has: a comma-separated list of names and\npresets (docker, podman, none, all), e.g. docker,SYS_ADMIN for Docker's defaults plus\nSYS_ADMIN. Resolves rules that depend on a capability, e.g. clone3 needs SYS_ADMIN")
	arch := fs.StringP("arch", "a", "", "the CPU `ARCH` to evaluate for, a Go, libseccomp or uname -m name such as amd64 or\nx86_64. For this machine's, pass \"$(uname -m)\". Resolves rules that depend on it")
	all := fs.BoolP("all", "A", false, "also list every syscall defined on --arch that has no rule left, with the\ndefault action.")
	showVersion := fs.Bool("version", false, "print the version and exit")
	kernel := fs.StringP("kernel", "k", "", "the kernel `VERSION` to evaluate for, such as 6.8 or 6.8.0-45-generic. For this machine's,\npass \"$(uname -r)\". Resolves rules that depend on a minimum kernel")
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, `usage: seccat [flags] [FILE|-]

Converts a Docker or Podman seccomp profile (JSON) to one line per rule, or with --json
back to JSON. Some rules only apply to certain capabilities, architectures or kernels.
Say what you know with --caps, --arch and --kernel. seccat does not look at the
machine it runs on: rules that depend on anything you leave out keep their condition
in the output.

`)
		_, _ = fmt.Fprint(stderr, fs.FlagUsages())
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 0
		}
		// pflag does not print the error when it is asked to return it.
		logf(stderr, "seccat: %v\nTry 'seccat --help' for more information.\n", err)
		return 2
	}
	if *showVersion {
		info, _ := debug.ReadBuildInfo()
		_, _ = fmt.Fprintf(stdout, "seccat %s\n", versionString(version, info))
		return 0
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	var ctx Context
	var err error
	if fs.Changed("caps") { // an empty value is an empty set, not a missing flag
		if ctx.Caps, err = parseCaps(*caps); err != nil {
			logf(stderr, "seccat: --caps: %v\n", err)
			return 2
		}
	}
	if *arch != "" {
		if ctx.Arch, err = parseArch(*arch); err != nil {
			logf(stderr, "seccat: --arch: %v\n", err)
			return 2
		}
	}
	if *kernel != "" {
		v, err := parseRelease(*kernel)
		if err != nil {
			logf(stderr, "seccat: --kernel: %v\n", err)
			return 2
		}
		ctx.Kernel = &v
	}
	if *toJSON && (fs.Changed("caps") || *arch != "" || *kernel != "" || *all) {
		logf(stderr, "seccat: --caps, --arch, --kernel and --all do not apply to --json\n")
		return 2
	}
	if *all {
		if ctx.Arch == "" {
			logf(stderr, "seccat: --all needs --arch\n")
			return 2
		}
		if ctx.Syscalls, err = syscallNames(ctx.Arch); err != nil {
			logf(stderr, "seccat: --all: %v\n", err)
			return 2
		}
	}
	if err := convert(fs.Arg(0), *toJSON, ctx, stdin, stdout, stderr); err != nil {
		logf(stderr, "seccat: %v\n", err)
		return 1
	}
	return 0
}

func openInput(name string, stdin io.Reader) (io.ReadCloser, error) {
	if name == "" || name == "-" {
		return io.NopCloser(stdin), nil
	}
	return os.Open(name)
}

func convert(name string, toJSON bool, ctx Context, stdin io.Reader, stdout, stderr io.Writer) error {
	in, err := openInput(name, stdin)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if toJSON {
		d, err := ParseText(in)
		if err != nil {
			return err
		}
		warn(stderr, d.Check())
		return d.Profile().Encode(stdout)
	}
	p, warnings, err := LoadProfile(in)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		logf(stderr, "seccat: warning: unknown field %s\n", w)
	}
	d, err := NewDoc(p)
	if err != nil {
		return err
	}
	warn(stderr, d.Check())
	d, warnings = d.Eval(ctx)
	warn(stderr, warnings)
	if ctx.Syscalls != nil {
		d = d.AddDefaults(ctx.Syscalls)
	}
	return d.WriteText(stdout)
}

func warn(w io.Writer, warnings []string) {
	for _, s := range warnings {
		logf(w, "seccat: warning: %s\n", s)
	}
}

// version can be set when building without version control information, as from
// a source tarball: go build -ldflags "-X main.version=1.2.3".
var version string

// versionString says which seccat this is: the override if there is one, else what
// Go recorded when it built the binary. That is the tag for go install
// github.com/...@v1.2.3, and a pseudo-version with the commit for a build from a
// git checkout.
func versionString(override string, info *debug.BuildInfo) string {
	if override != "" {
		return override
	}
	if info == nil {
		return "unknown"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return "devel"
	}
	details := []string{revision[:min(7, len(revision))]}
	if modified == "true" {
		details = append(details, "modified")
	}
	return "devel (" + strings.Join(details, ", ") + ")"
}

// logf writes diagnostics; a failing stderr leaves nowhere to report to.
func logf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

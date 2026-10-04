// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	vcs := func(revision, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: revision}, {Key: "vcs.modified", Value: modified}}
	}
	for name, tt := range map[string]struct {
		override string
		info     *debug.BuildInfo
		want     string
	}{
		"override wins":          {"1.2.3", &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}}, "1.2.3"},
		"tagged install":         {"", &debug.BuildInfo{Main: debug.Module{Version: "v0.3.1"}}, "v0.3.1"},
		"pseudo-version":         {"", &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261004102743-3789a5a99871+dirty"}}, "v0.0.0-20261004102743-3789a5a99871+dirty"},
		"devel with a commit":    {"", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs("0123456789abcdef", "false")}, "devel (0123456)"},
		"devel, modified":        {"", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs("0123456789abcdef", "true")}, "devel (0123456, modified)"},
		"empty version, a build": {"", &debug.BuildInfo{Settings: vcs("abc", "false")}, "devel (abc)"},
		"devel, no vcs":          {"", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "devel"},
		"nothing recorded":       {"", &debug.BuildInfo{}, "devel"},
		"no build info":          {"", nil, "unknown"},
	} {
		if got := versionString(tt.override, tt.info); got != tt.want {
			t.Errorf("%s: got %q, want %q", name, got, tt.want)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	// The nil stdin would panic if --version tried to read input.
	for _, args := range [][]string{{"--version"}, {"--version", "testdata/nonexistent.json"}, {"--version", "--caps", "BOGUS"}} {
		out, stderr, code := runText(t, args...)
		if code != 0 || stderr != "" || !strings.HasPrefix(out, "seccat ") || !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, stderr)
		}
	}
	// The version is the one the binary reports for itself, never empty.
	out, _, _ := runText(t, "--version")
	if strings.TrimSpace(strings.TrimPrefix(out, "seccat ")) == "" {
		t.Errorf("empty version: %q", out)
	}
}

// --version wins over everything else on the command line, including too many files.
func TestVersionFlagComesFirst(t *testing.T) {
	if out, _, code := runText(t, "--version", "a.json", "b.json"); code != 0 || !strings.HasPrefix(out, "seccat ") {
		t.Errorf("exit %d, stdout %q", code, out)
	}
}

// An unknown or incomplete option fails with a message, not silently.
func TestUnknownOptions(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string // part of the message that names the problem
	}{
		{[]string{"-x"}, "'x'"},
		{[]string{"-x", "testdata/docker.json"}, "'x'"},
		{[]string{"-Ax", "-a", "amd64", "testdata/docker.json"}, "'x'"},
		{[]string{"--bogus", "testdata/docker.json"}, "--bogus"},
		{[]string{"--cap", "docker", "testdata/docker.json"}, "--cap"}, // no abbreviations
		{[]string{"-a"}, "needs an argument"},
		{[]string{"--kernel"}, "needs an argument"},
	} {
		out, stderr, code := runText(t, tt.args...)
		if code != 2 || out != "" || !strings.HasPrefix(stderr, "seccat: ") || !strings.Contains(stderr, tt.want) || !strings.Contains(stderr, "--help") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", tt.args, code, out, stderr)
		}
	}
}

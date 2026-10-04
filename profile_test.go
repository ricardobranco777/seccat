// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func loadFile(t *testing.T, path string) (*Profile, []string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	p, warnings, err := LoadProfile(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return p, warnings
}

func TestLoadSnapshots(t *testing.T) {
	for _, path := range []string{"testdata/docker.json", "testdata/podman.json"} {
		p, warnings := loadFile(t, path)
		if len(warnings) != 0 {
			t.Errorf("%s: unexpected warnings %v", path, warnings)
		}
		if p.DefaultAction != "SCMP_ACT_ERRNO" || len(p.Syscalls) == 0 {
			t.Errorf("%s: bad profile: %q, %d entries", path, p.DefaultAction, len(p.Syscalls))
		}
	}
}

func TestLoadErrors(t *testing.T) {
	const ok = `"defaultAction":"SCMP_ACT_ERRNO"`
	tests := []struct{ name, in, want string }{
		{"bad json", `{`, "decoding profile"},
		{"bad default action", `{"defaultAction":"NOPE"}`, "defaultAction"},
		{"name and names", `{` + ok + `,"syscalls":[{"name":"a","names":["b"],"action":"SCMP_ACT_ALLOW"}]}`, "syscalls[0]: both"},
		{"no names", `{` + ok + `,"syscalls":[{"action":"SCMP_ACT_ALLOW"}]}`, "no syscall names"},
		{"bad action", `{` + ok + `,"syscalls":[{"names":["a"],"action":"X"}]}`, `unknown action "X"`},
		{"bad op", `{` + ok + `,"syscalls":[{"names":["a"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"BAD"}]}]}`, "unknown op"},
		{"bad index", `{` + ok + `,"syscalls":[{"names":["a"],"action":"SCMP_ACT_ALLOW","args":[{"index":6,"op":"SCMP_CMP_EQ"}]}]}`, "out of range"},
		{"bad kernel", `{` + ok + `,"syscalls":[{"names":["a"],"action":"SCMP_ACT_ALLOW","includes":{"minKernel":"4"}}]}`, "includes.minKernel"},
	}
	for _, tt := range tests {
		_, _, err := LoadProfile(strings.NewReader(tt.in))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want containing %q", tt.name, err, tt.want)
		}
	}
}

func TestUnknownFields(t *testing.T) {
	in := `{"defaultAction":"SCMP_ACT_ALLOW","extra":1,"archMap":[{"architecture":"x","foo":1}],
	"syscalls":[{"names":["a"],"action":"SCMP_ACT_ALLOW","bar":1,"includes":{"baz":1},
	"args":[{"index":0,"op":"SCMP_CMP_EQ","qux":1}]}]}`
	_, warnings, err := LoadProfile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"archMap[0].foo", "extra", "syscalls[0].args[0].qux", "syscalls[0].bar",
		"syscalls[0].includes.baz",
	}
	if !slices.Equal(warnings, want) {
		t.Errorf("warnings = %v, want %v", warnings, want)
	}
}

func TestParseVersion(t *testing.T) {
	if v, err := parseVersion("4.10.2"); err != nil || v != (Version{4, 10, 2}) {
		t.Errorf("got %v, %v", v, err)
	}
	for _, bad := range []string{"", "4", "a.b", "1.2.3.4", "-1.0"} {
		if _, err := parseVersion(bad); err == nil {
			t.Errorf("parseVersion(%q) succeeded", bad)
		}
	}
}

// Docker and Podman write their profiles without a final newline.
func TestEncodeHasNoFinalNewline(t *testing.T) {
	for _, path := range []string{"testdata/docker.json", "testdata/podman.json", "testdata/log-only.json"} {
		p, _ := loadFile(t, path)
		var buf strings.Builder
		if err := p.Encode(&buf); err != nil {
			t.Fatal(err)
		}
		if out := buf.String(); !strings.HasSuffix(out, "}") {
			t.Errorf("%s: output ends with %q", path, out[max(0, len(out)-3):])
		}
	}
}

// Docker and Podman write their profiles with tab indentation; matching it keeps
// the diff between a profile and its round trip small.
func TestEncodeIndentsWithTabs(t *testing.T) {
	p, _ := loadFile(t, "testdata/docker.json")
	var buf strings.Builder
	if err := p.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(buf.String(), "\n")
	if lines[0] != "{" || !strings.HasPrefix(lines[1], "\t\"defaultAction\"") {
		t.Errorf("first lines: %q", lines[:2])
	}
	for _, l := range lines {
		if strings.HasPrefix(l, " ") {
			t.Fatalf("line indented with spaces: %q", l)
		}
	}
}

// The --kernel flag takes a release as uname -r prints it. Only the leading
// X.Y[.Z] counts.
func TestParseRelease(t *testing.T) {
	tests := map[string]Version{
		"7.2.8-200.fc44.x86_64": {7, 2, 8},  // Fedora
		"7.0.0-1020-raspi":      {7, 0, 0},  // Ubuntu
		"6.1.0-18-amd64":        {6, 1, 0},  // Debian
		"6.8.2-arch1-1":         {6, 8, 2},  // Arch
		"6.6.14-0-lts":          {6, 6, 14}, // Alpine
		"3.12.25-gentoo":        {3, 12, 25},
		"3.12-1-amd64":          {3, 12, 0}, // only two numbers before the suffix
		"5.10.103+":             {5, 10, 103},
		"6.8":                   {6, 8, 0},
		"6.8.1":                 {6, 8, 1},
		"4.8.1.2":               {4, 8, 1},
	}
	for in, want := range tests {
		if got, err := parseRelease(in); err != nil || got != want {
			t.Errorf("parseRelease(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	// Surrounding whitespace, as from a trailing newline, is harmless.
	for _, in := range []string{"6.8\n", " 6.8 "} {
		if got, err := parseRelease(in); err != nil || got != (Version{6, 8, 0}) {
			t.Errorf("parseRelease(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "6", "6.", ".6", "a.b", "-6.8", "kernel 6.8", "v6.8", "6,8"} {
		if _, err := parseRelease(bad); err == nil {
			t.Errorf("parseRelease(%q) succeeded", bad)
		}
	}
}

// A profile's minKernel stays strict: a suffix there is a mistake, not a release.
func TestMinKernelStaysStrict(t *testing.T) {
	for _, bad := range []string{"4.8-foo", "4.8.1-1020", "4.8.1.2", "4.8+"} {
		in := `{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["x"],"action":"SCMP_ACT_ALLOW","includes":{"minKernel":"` + bad + `"}}]}`
		if _, _, err := LoadProfile(strings.NewReader(in)); err == nil {
			t.Errorf("minKernel %q accepted", bad)
		}
		if _, err := ParseText(strings.NewReader("@default\tALLOW\nx\tALLOW\tkernel>=" + bad + "\n")); err == nil {
			t.Errorf("kernel>=%s accepted in text", bad)
		}
	}
}

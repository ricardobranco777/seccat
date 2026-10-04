// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"slices"
	"strings"
	"testing"
)

func mustCaps(t *testing.T, s string) map[string]bool {
	t.Helper()
	c, err := parseCaps(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustVersion(t *testing.T, s string) *Version {
	t.Helper()
	v, err := parseVersion(s)
	if err != nil {
		t.Fatal(err)
	}
	return &v
}

// evalLines evaluates a snapshot and returns the lines for one syscall.
func evalLines(t *testing.T, snapshot, syscall string, ctx Context) []string {
	t.Helper()
	p, _ := loadFile(t, "testdata/"+snapshot+".json")
	d, err := NewDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	d, _ = d.Eval(ctx)
	var out []string
	for l := range strings.SplitSeq(docText(t, d), "\n") {
		if strings.HasPrefix(l, syscall+"\t") {
			out = append(out, l)
		}
	}
	return out
}

func TestEval(t *testing.T) {
	tests := []struct {
		name, snapshot, syscall string
		ctx                     func(t *testing.T) Context
		want                    []string
	}{
		{"clone3 docker caps", "docker", "clone3",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "docker")} },
			[]string{"clone3\tERRNO(ENOSYS)"}},
		{"clone3 all caps", "docker", "clone3",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "all")} },
			[]string{"clone3\tALLOW"}},
		{"clone3 caps unknown", "docker", "clone3",
			func(t *testing.T) Context { return Context{} },
			[]string{"clone3\tALLOW\tcap:SYS_ADMIN", "clone3\tERRNO(ENOSYS)\t!cap:SYS_ADMIN"}},
		{"ptrace old kernel", "docker", "ptrace",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "docker"), Kernel: mustVersion(t, "4.7")} },
			nil},
		{"ptrace 4.8", "docker", "ptrace",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "docker"), Kernel: mustVersion(t, "4.8")} },
			[]string{"ptrace\tALLOW"}},
		{"ptrace numeric compare 4.10", "docker", "ptrace",
			func(t *testing.T) Context {
				return Context{Caps: mustCaps(t, "docker"), Kernel: mustVersion(t, "4.10")}
			},
			[]string{"ptrace\tALLOW"}},
		{"ptrace kernel unknown", "docker", "ptrace",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "docker")} },
			[]string{"ptrace\tALLOW\tkernel>=4.8"}},
		{"chroot podman none", "podman", "chroot",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "none")} },
			[]string{"chroot\tERRNO(EPERM)"}},
		{"chroot podman caps", "podman", "chroot",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "podman")} },
			[]string{"chroot\tALLOW"}},
		{"socket podman none", "podman", "socket",
			func(t *testing.T) Context { return Context{Caps: mustCaps(t, "none")} },
			[]string{
				"socket\tALLOW\targ0!=AF_NETLINK",
				"socket\tALLOW\targ2!=9",
				"socket\tALLOW\targ2!=9",
				"socket\tERRNO(EINVAL)\targ0==AF_NETLINK && arg2==NETLINK_AUDIT",
			}},
		{"clone amd64", "docker", "clone",
			func(t *testing.T) Context { return Context{Arch: "amd64", Caps: mustCaps(t, "docker")} },
			[]string{"clone\tALLOW\targ0&(CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET)==0"}},
		{"clone s390x", "docker", "clone",
			func(t *testing.T) Context { return Context{Arch: "s390x", Caps: mustCaps(t, "docker")} },
			[]string{"clone\tALLOW\targ1&(CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET)==0\t# s390 parameter ordering for clone is different"}},
		{"arch gated rule", "docker", "arch_prctl",
			func(t *testing.T) Context { return Context{Arch: "arm64"} },
			nil},
		{"arch gated rule kept", "docker", "arch_prctl",
			func(t *testing.T) Context { return Context{Arch: "amd64"} },
			[]string{"arch_prctl\tALLOW"}},
	}
	for _, tt := range tests {
		if got := evalLines(t, tt.snapshot, tt.syscall, tt.ctx(t)); !slices.Equal(got, tt.want) {
			t.Errorf("%s:\ngot  %q\nwant %q", tt.name, got, tt.want)
		}
	}
}

func TestEvalHeaderArch(t *testing.T) {
	d := mustParse(t, "@default\tKILL\n@arch\tx86_64\tx86,x32\n@arch\taarch64\tarm\n")
	got, warnings := d.Eval(Context{Arch: "arm64"})
	if want := "@default\tKILL\n@arch\taarch64\tarm\n"; docText(t, got) != want || len(warnings) != 0 {
		t.Errorf("got %q %v", docText(t, got), warnings)
	}
	if _, warnings := d.Eval(Context{Arch: "riscv64"}); len(warnings) != 1 {
		t.Errorf("want a warning for an arch with no @arch entry, got %v", warnings)
	}
	// Without --arch the header is untouched.
	if got, _ := d.Eval(Context{}); docText(t, got) != docText(t, d) {
		t.Error("header changed without --arch")
	}
}

func TestParseFlags(t *testing.T) {
	if _, err := parseCaps("SYS_ADMIN,cap_bpf"); err != nil {
		t.Error(err)
	}
	if c, _ := parseCaps("none"); c == nil || len(c) != 0 {
		t.Errorf("none must be a known empty set, got %v", c)
	}
	if len(mustCaps(t, "all")) != 41 {
		t.Error("all should have 41 capabilities")
	}
	if _, err := parseCaps("SYS_BOGUS"); err == nil {
		t.Error("unknown cap accepted")
	}
	for _, bad := range []string{"docker,SYS_BOGUS", "docker,", ",docker", "docker,,BPF"} {
		if _, err := parseCaps(bad); err == nil {
			t.Errorf("parseCaps(%q) succeeded", bad)
		}
	}
	if _, err := parseArch("sparc64"); err == nil || !strings.Contains(err.Error(), "uname -m") {
		t.Errorf("unsupported architecture: got %v", err)
	}
}

func TestParseArch(t *testing.T) {
	tests := map[string]string{
		// native names, as arch: conditions write them
		"amd64": "amd64", "x86": "x86", "arm64": "arm64", "arm": "arm", "s390x": "s390x", "s390": "s390",
		"riscv64": "riscv64", "ppc64le": "ppc64le", "ppc64": "ppc64", "ppc": "ppc", "loongarch64": "loongarch64",
		"mips": "mips", "mips64": "mips64", "mipsel": "mipsel", "mipsel64": "mipsel64",
		"mips64n32": "mips64n32", "mips3l64n32": "mips3l64n32",
		// Go names that differ
		"386": "x86", "loong64": "loongarch64", "mipsle": "mipsel", "mips64le": "mipsel64",
		"mips64p32": "mips64n32", "mips64p32le": "mips3l64n32",
		// libseccomp names that differ
		"x86_64": "amd64", "aarch64": "arm64", "mipsel64n32": "mips3l64n32",
		// uname -m
		"i386": "x86", "i486": "x86", "i586": "x86", "i686": "x86",
		"armv5tel": "arm", "armv6l": "arm", "armv7l": "arm", "armv8l": "arm",
		// case
		"X86_64": "amd64", "Aarch64": "arm64",
	}
	for in, want := range tests {
		if got, err := parseArch(in); err != nil || got != want {
			t.Errorf("parseArch(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// $(uname -m) has no newline, but trailing whitespace from other sources is harmless.
	if got, err := parseArch(" aarch64\n"); err != nil || got != "arm64" {
		t.Errorf("whitespace not trimmed: %q, %v", got, err)
	}
	for _, bad := range []string{"", "x32", "sparc64", "ppc64el", "armhf", "aarch64_be", "armv7b", "arm64be", "i786"} {
		if _, err := parseArch(bad); err == nil {
			t.Errorf("parseArch(%q) succeeded", bad)
		}
	}
	// No name may belong to two architectures.
	if len(archNameConflicts) != 0 {
		t.Errorf("names with two meanings: %v", archNameConflicts)
	}
}

// mobyGoToNative and mobyNativeToSeccomp are moby's tables, copied from
// profiles/seccomp/seccomp_linux.go. includes.arches and excludes.arches are
// compared with goToNative[runtime.GOARCH].
var mobyGoToNative = map[string]string{
	"386": "x86", "amd64": "amd64", "arm": "arm", "arm64": "arm64", "loong64": "loongarch64",
	"mips64": "mips64", "mips64p32": "mips64n32", "mips64le": "mipsel64", "mips64p32le": "mips3l64n32",
	"mipsle": "mipsel", "ppc": "ppc", "ppc64": "ppc64", "ppc64le": "ppc64le", "riscv64": "riscv64",
	"s390": "s390", "s390x": "s390x",
}

// moby's nativeToSeccomp keys "loong64" and "mipsle" do not match the values its
// goToNative gives ("loongarch64" and "mipsel"), so those two are left out here.
var mobyNativeToSeccomp = map[string]string{
	"x86": "x86", "amd64": "x86_64", "arm": "arm", "arm64": "aarch64", "mips64": "mips64",
	"mips64n32": "mips64n32", "mipsel64": "mipsel64", "mips3l64n32": "mipsel64n32", "ppc": "ppc",
	"ppc64": "ppc64", "ppc64le": "ppc64le", "riscv64": "riscv64", "s390": "s390", "s390x": "s390x",
}

func TestArchTableMatchesMoby(t *testing.T) {
	for goarch, native := range mobyGoToNative {
		if got, err := parseArch(goarch); err != nil || got != native {
			t.Errorf("--arch %s resolves to %q (%v); moby's native name is %q", goarch, got, err, native)
		}
	}
	for native, want := range mobyNativeToSeccomp {
		if got := seccompName(native); got != want {
			t.Errorf("@arch name of %s is %q, moby has %q", native, got, want)
		}
	}
}

func TestArchFlagAliases(t *testing.T) {
	var a, b strings.Builder
	var errb strings.Builder
	for _, tt := range [][2]string{{"amd64", "x86_64"}, {"arm64", "aarch64"}, {"x86", "386"}, {"386", "i686"}, {"arm", "armv7l"}, {"loongarch64", "loong64"}} {
		a.Reset()
		b.Reset()
		if run([]string{"--all", "--arch", tt[0], "--caps", "docker", "testdata/docker.json"}, nil, &a, &errb) != 0 ||
			run([]string{"--all", "--arch", tt[1], "--caps", "docker", "testdata/docker.json"}, nil, &b, &errb) != 0 {
			t.Fatal(errb.String())
		}
		if a.String() != b.String() || a.Len() == 0 {
			t.Errorf("--arch %s and --arch %s differ", tt[0], tt[1])
		}
	}
}

// refKeep is an independent transcription of the filter loop in moby's
// setupSeccomp, applied to the raw JSON entry instead of to the text rules. arch
// is the native name, goToNative[runtime.GOARCH] in moby, e.g. x86 for 386.
func refKeep(e *Entry, caps map[string]bool, arch string, kernel Version) bool {
	if f := e.Excludes; f != nil {
		if slices.Contains(f.Arches, arch) {
			return false
		}
		for _, c := range f.Caps {
			if caps[strings.TrimPrefix(c, "CAP_")] {
				return false
			}
		}
		if f.MinKernel != nil {
			if v, _ := parseVersion(*f.MinKernel); slices.Compare(kernel[:], v[:]) >= 0 {
				return false
			}
		}
	}
	if f := e.Includes; f != nil {
		if len(f.Arches) > 0 && !slices.Contains(f.Arches, arch) {
			return false
		}
		for _, c := range f.Caps {
			if !caps[strings.TrimPrefix(c, "CAP_")] {
				return false
			}
		}
		if f.MinKernel != nil {
			if v, _ := parseVersion(*f.MinKernel); slices.Compare(kernel[:], v[:]) < 0 {
				return false
			}
		}
	}
	return true
}

// TestEvalMatchesReference checks every preset x arch x kernel combination on
// both snapshots, both directly and after a trip through the text format.
func TestEvalMatchesReference(t *testing.T) {
	for _, snapshot := range []string{"docker", "podman"} {
		p, _ := loadFile(t, "testdata/"+snapshot+".json")
		d, err := NewDoc(p)
		if err != nil {
			t.Fatal(err)
		}
		reparsed := mustParse(t, docText(t, d))
		for _, preset := range []string{"docker", "podman", "none", "all"} {
			for _, arch := range []string{"amd64", "arm64", "s390x", "x86"} {
				for _, kernel := range []string{"4.7", "4.8", "4.10", "6.8"} {
					caps, ver := mustCaps(t, preset), *mustVersion(t, kernel)
					want := map[string]int{}
					for i := range p.Syscalls {
						if refKeep(&p.Syscalls[i], caps, arch, ver) {
							for _, n := range p.Syscalls[i].AllNames() {
								want[n]++
							}
						}
					}
					ctx := Context{Caps: caps, Arch: arch, Kernel: &ver}
					for _, src := range []*Doc{d, reparsed} {
						res, _ := src.Eval(ctx)
						got := map[string]int{}
						for _, r := range res.Rules {
							got[r.Name]++
							if r.Conds.Caps != nil || r.Conds.NotCaps != nil || r.Conds.Arches != nil ||
								r.Conds.NotArches != nil || r.Conds.KernelGE != "" || r.Conds.KernelLT != "" {
								t.Fatalf("%s/%s/%s/%s: condition left over in %v", snapshot, preset, arch, kernel, r)
							}
						}
						if len(got) != len(want) {
							t.Errorf("%s/%s/%s/%s: %d syscalls, want %d", snapshot, preset, arch, kernel, len(got), len(want))
							continue
						}
						for n, c := range want {
							if got[n] != c {
								t.Errorf("%s/%s/%s/%s: %s has %d rules, want %d", snapshot, preset, arch, kernel, n, got[n], c)
							}
						}
					}
				}
			}
		}
	}
}

func TestRunFlags(t *testing.T) {
	var out, errb strings.Builder
	args := []string{"--caps", "docker", "--arch", "amd64", "--kernel", "6.8", "testdata/docker.json"}
	if code := run(args, nil, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "ptrace\tALLOW\n") || strings.Contains(out.String(), "cap:") {
		t.Error("flags were not applied")
	}
	for _, bad := range [][]string{
		{"--caps", "BOGUS"}, {"--arch", "sparc64"}, {"--kernel", "6"}, {"-j", "--caps", "docker"},
	} {
		if code := run(bad, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", bad, code)
		}
	}
}

func TestHelp(t *testing.T) {
	var out, errb strings.Builder
	if code := run([]string{"-h"}, nil, &out, &errb); code != 0 {
		t.Errorf("-h exit %d", code)
	}
	for _, want := range []string{"-c, --caps SET", "-a, --arch ARCH", "-k, --kernel VERSION", "-A, --all", "-j, --json", "--version", "capabilities the container has", "clone3", "does not look at the\nmachine it runs on"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("help is missing %q:\n%s", want, errb.String())
		}
	}
}

func TestOptionForms(t *testing.T) {
	render := func(args ...string) string {
		t.Helper()
		var out, errb strings.Builder
		if code := run(args, nil, &out, &errb); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errb.String())
		}
		return out.String()
	}
	want := render("--caps", "docker", "--arch", "amd64", "--kernel", "6.8", "--all", "testdata/docker.json")
	for _, args := range [][]string{
		{"-c", "docker", "-a", "amd64", "-k", "6.8", "-A", "testdata/docker.json"}, // short options
		{"--caps=docker", "--arch=amd64", "--kernel=6.8", "--all", "testdata/docker.json"},
		{"-c=docker", "-a=amd64", "-k=6.8", "-A", "testdata/docker.json"},
		{"-cdocker", "-aamd64", "-k6.8", "-A", "testdata/docker.json"},
		{"-Aa", "amd64", "-c", "docker", "-k", "6.8", "testdata/docker.json"},      // clustered
		{"testdata/docker.json", "-c", "docker", "-a", "amd64", "-k", "6.8", "-A"}, // flags after the file
		{"-c", "docker", "testdata/docker.json", "-a", "amd64", "-k", "6.8", "-A"},
		{"-c", "docker", "-a", "amd64", "-k", "6.8", "-A", "--", "testdata/docker.json"},
	} {
		if got := render(args...); got != want {
			t.Errorf("%v: output differs", args)
		}
	}

	// --json is the long form of -j, and stdin can be named with "-".
	text := render("testdata/podman.json")
	for _, flag := range []string{"-j", "--json"} {
		var out, errb strings.Builder
		if code := run([]string{flag, "-"}, strings.NewReader(text), &out, &errb); code != 0 || !strings.Contains(out.String(), `"defaultAction"`) {
			t.Errorf("%s -: exit %d: %s", flag, code, errb.String())
		}
	}

	// A single dash starts short options, so -caps is the cluster -c -a -p -s and is rejected.
	var out, errb strings.Builder
	if code := run([]string{"-caps", "docker", "testdata/docker.json"}, nil, &out, &errb); code == 0 {
		t.Error("-caps unexpectedly accepted")
	}
	// Two files is still an error.
	if code := run([]string{"a.json", "b.json"}, nil, &out, &errb); code != 2 {
		t.Errorf("two files: exit %d, want 2", code)
	}
}

func TestParseCapsMixesPresetsAndNames(t *testing.T) {
	dockerCaps := mustCaps(t, "docker")
	for _, in := range []string{"docker,SYS_ADMIN", "Docker, cap_sys_admin", "SYS_ADMIN,docker", " docker , SYS_ADMIN "} {
		got := mustCaps(t, in)
		if len(got) != len(dockerCaps)+1 || !got["SYS_ADMIN"] || !got["CHOWN"] {
			t.Errorf("%q: got %d caps, want Docker's %d plus SYS_ADMIN", in, len(got), len(dockerCaps))
		}
	}
	if got := mustCaps(t, "none,BPF"); len(got) != 1 || !got["BPF"] {
		t.Errorf("none,BPF: got %v", got)
	}
	if got := mustCaps(t, "docker,podman"); len(got) != len(dockerCaps) {
		t.Errorf("docker,podman: got %d caps, want the union (%d)", len(got), len(dockerCaps))
	}
	if got := mustCaps(t, "docker,all"); len(got) != 41 {
		t.Errorf("docker,all: got %d caps, want all 41", len(got))
	}

	// What --cap-add SYS_ADMIN changes in Docker's profile: clone3 opens up.
	ctx := Context{Caps: mustCaps(t, "docker,SYS_ADMIN"), Arch: "amd64", Kernel: mustVersion(t, "6.8")}
	if got := evalLines(t, "docker", "clone3", ctx); !slices.Equal(got, []string{"clone3\tALLOW"}) {
		t.Errorf("clone3 with docker,SYS_ADMIN: %q", got)
	}
}

// An empty --caps is an empty capability set, as capsh --print shows for a
// container with every capability dropped. It is not the same as leaving the flag out.
func TestEmptyCaps(t *testing.T) {
	for _, in := range []string{"", " ", "none"} {
		got, err := parseCaps(in)
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("parseCaps(%q) = %v, %v; want a known, empty set", in, got, err)
		}
	}

	capConditions := func(args ...string) int {
		t.Helper()
		out, stderr, code := runText(t, append(args, "testdata/docker.json")...)
		if code != 0 || stderr != "" {
			t.Fatalf("%v: exit %d: %s", args, code, stderr)
		}
		return strings.Count(out, "cap:")
	}
	if n := capConditions("-a", "amd64", "-k", "6.8"); n == 0 {
		t.Fatal("without --caps, the capability conditions should stay")
	}
	for _, args := range [][]string{
		{"--caps", "", "-a", "amd64", "-k", "6.8"},
		{"--caps=", "-a", "amd64", "-k", "6.8"},
		{"-c", " ", "-a", "amd64", "-k", "6.8"},
		{"--caps", "none", "-a", "amd64", "-k", "6.8"},
	} {
		if n := capConditions(args...); n != 0 {
			t.Errorf("%v: %d capability conditions left, want 0", args, n)
		}
	}

	// A given --caps does not combine with --json, whatever its value.
	if _, stderr, code := runText(t, "-j", "--caps", ""); code != 2 || !strings.Contains(stderr, "do not apply") {
		t.Errorf("-j with an empty --caps: exit %d, stderr %q", code, stderr)
	}
}

// A 32-bit x86 host is "x86" in a profile's conditions, which is not its Go name.
// Docker's and Podman's profiles allow modify_ldt on amd64, x32 and x86 only.
func TestX86ConditionsApply(t *testing.T) {
	for _, snapshot := range []string{"docker", "podman"} {
		for _, name := range []string{"386", "x86", "i686"} {
			out, stderr, code := runText(t, "--arch", name, "--caps", "none", "testdata/"+snapshot+".json")
			if code != 0 {
				t.Fatalf("%s --arch %s: exit %d: %s", snapshot, name, code, stderr)
			}
			if !strings.Contains(out, "\nmodify_ldt\tALLOW\n") {
				t.Errorf("%s --arch %s: modify_ldt is not allowed", snapshot, name)
			}
		}
		if out, _, _ := runText(t, "--arch", "arm64", "--caps", "none", "testdata/"+snapshot+".json"); strings.Contains(out, "\nmodify_ldt\t") {
			t.Errorf("%s --arch arm64: modify_ldt should have no rule", snapshot)
		}
	}
}

// --kernel "$(uname -r)" works, and means the same as the X.Y[.Z] it starts with.
func TestKernelFlagTakesAnUnameRelease(t *testing.T) {
	ptrace := func(kernel string) string {
		t.Helper()
		out, stderr, code := runText(t, "--caps", "docker", "--arch", "amd64", "--kernel", kernel, "testdata/docker.json")
		if code != 0 || stderr != "" {
			t.Fatalf("--kernel %q: exit %d: %s", kernel, code, stderr)
		}
		for l := range strings.SplitSeq(out, "\n") {
			if strings.HasPrefix(l, "ptrace\t") {
				return l
			}
		}
		return "" // no rule left: denied
	}
	// Docker's ptrace rule needs kernel 4.8.
	for _, tt := range []struct{ release, want string }{
		{"4.7.9-200.fc44.x86_64", ""},
		{"4.8.0-1020-raspi", "ptrace\tALLOW"},
		{"7.0.0-1020-raspi", "ptrace\tALLOW"},
		{"3.12-1-amd64", ""},
		{"4.10.3-arch1-1", "ptrace\tALLOW"}, // 4.10 is newer than 4.8
	} {
		if got := ptrace(tt.release); got != tt.want {
			t.Errorf("--kernel %s: ptrace line %q, want %q", tt.release, got, tt.want)
		}
	}
	if a, b := ptrace("7.0.0-1020-raspi"), ptrace("7.0.0"); a != b {
		t.Errorf("a release and its X.Y.Z differ: %q vs %q", a, b)
	}
}

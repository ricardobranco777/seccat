// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"slices"
	"strings"
	"testing"
)

func TestSyscallTable(t *testing.T) {
	// Loading panics on a malformed embedded file, so this guards the shipped data.
	tbl := loadSyscalls()
	if len(tbl.byArch) < 15 {
		t.Errorf("only %d architectures", len(tbl.byArch))
	}
	has := func(arch, name string) bool { return slices.Contains(tbl.byArch[arch], name) }
	for _, c := range []struct {
		arch, name string
		want       bool
	}{
		{"x86_64", "read", true},
		{"x86_64", "clone3", true},
		{"x86_64", "arch_prctl", true},
		{"aarch64", "arch_prctl", false}, // x86 only
		{"x86", "_llseek", true},         // 32-bit only
		{"x86_64", "_llseek", false},
	} {
		if got := has(c.arch, c.name); got != c.want {
			t.Errorf("%s has %s = %v, want %v", c.arch, c.name, got, c.want)
		}
	}
	if !slices.IsSorted(tbl.byArch["x86_64"]) {
		t.Error("names not sorted")
	}
}

func TestParseSyscallsErrors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":      "",
		"no header":  "read,1\n",
		"even cols":  "#syscall,x86,x86_kver,x32\nread,1,K,1\n",
		"bad number": "#syscall (v),x86,x86_kver\nread,abc,K\n",
		"ragged":     "#syscall (v),x86,x86_kver\nread,1\n",
	} {
		if _, err := parseSyscalls(in); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	tbl, err := parseSyscalls("#syscall (v),x86,x86_kver,arm,arm_kver\nb,1,K,PNR,K\na,2,K,3,K\n")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tbl.byArch["x86"], []string{"a", "b"}) || !slices.Equal(tbl.byArch["arm"], []string{"a"}) {
		t.Errorf("got %v", tbl.byArch)
	}
}

func TestSyscallNamesPerArch(t *testing.T) {
	// Every architecture seccat accepts for --arch has a table.
	for _, a := range arches {
		names, err := syscallNames(a.native)
		if err != nil || len(names) < 250 {
			t.Errorf("%s: %d names, %v", a.native, len(names), err)
		}
	}
	// Little-endian variants resolve with their big-endian table.
	for _, pair := range [][2]string{{"mips", "mipsel"}, {"mips64", "mipsel64"}, {"mips64n32", "mips3l64n32"}, {"ppc64", "ppc64le"}} {
		a, _ := syscallNames(pair[0])
		b, _ := syscallNames(pair[1])
		if !slices.Equal(a, b) {
			t.Errorf("%s differs from %s", pair[1], pair[0])
		}
	}
}

func TestAll(t *testing.T) {
	run1 := func(args ...string) (string, int) {
		var out, errb strings.Builder
		code := run(args, nil, &out, &errb)
		return out.String() + errb.String(), code
	}
	out, code := run1("--all", "--arch", "amd64", "--caps", "docker", "--kernel", "4.7", "testdata/docker.json")
	if code != 0 {
		t.Fatal(out)
	}
	lines := strings.Split(out, "\n")
	for _, want := range []string{
		"kexec_load\tERRNO(EPERM)", // never mentioned by the profile
		"ptrace\tERRNO(EPERM)",     // every rule evaluated away
		"read\tALLOW",              // has a rule, not duplicated
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("missing line %q", want)
		}
	}
	if n := strings.Count(out, "\nread\t"); n != 1 {
		t.Errorf("read listed %d times", n)
	}
	if strings.Contains(out, "\ngtty\t") { // defined on x86 only, and not named by the profile
		t.Error("32-bit-only syscall listed for amd64")
	}
	if out, _ := run1("--all", "--arch", "386", "--caps", "docker", "testdata/docker.json"); !strings.Contains(out, "\ngtty\tERRNO(EPERM)\n") {
		t.Error("gtty missing for 386")
	}

	// Podman has a different default, and an explicit EPERM deny-list on top of it.
	out, _ = run1("--all", "--arch", "amd64", "--caps", "podman", "testdata/podman.json")
	lines = strings.Split(out, "\n")
	for _, want := range []string{
		"add_key\tERRNO(ENOSYS)",   // unmentioned: falls to the default
		"kexec_load\tERRNO(EPERM)", // explicit rule
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("podman: missing line %q", want)
		}
	}

	// The other supported architectures work too.
	for _, arch := range []string{"s390x", "riscv64", "ppc64le", "loong64", "386", "arm"} {
		if out, code := run1("--all", "--arch", arch, "--caps", "docker", "testdata/docker.json"); code != 0 || !strings.Contains(out, "\nkexec_load\t") {
			t.Errorf("--all on %s: exit %d", arch, code)
		}
	}

	if out, code := run1("--all", "testdata/docker.json"); code != 2 || !strings.Contains(out, "needs --arch") {
		t.Errorf("--all without --arch: %d %q", code, out)
	}
	if _, code := run1("--all", "-j"); code != 2 {
		t.Errorf("--all with -j: exit %d", code)
	}
}

func TestCheckUnknownSyscall(t *testing.T) {
	d := mustParse(t, "@default\tKILL\nptrcae\tALLOW\nread\tALLOW\nptrcae\tERRNO\nzzz\tALLOW\n")
	want := []string{"unknown syscall ptrcae", "unknown syscall zzz"}
	if got := d.Check(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

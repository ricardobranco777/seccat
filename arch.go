// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// arch is one architecture under the names that are in use for it.
//
// The identity seccat uses, and that includes.arches and excludes.arches are
// compared with, is the native name: moby derives it from runtime.GOARCH through
// goToNative (profiles/seccomp/seccomp_linux.go). It differs from the Go name for
// 386 (x86) and a few others, and a profile that says x86 means a 32-bit x86 host.
type arch struct {
	native  string // name used in profile conditions
	goarch  string // GOARCH, when it differs from native
	seccomp string // @arch name: libseccomp's, without SCMP_ARCH_ and in lower case
}

// arches follows moby's goToNative and nativeToSeccomp. Plain mips is not in
// moby's tables; it is here because libseccomp, runc and Go have it.
var arches = []arch{
	{"x86", "386", "x86"},
	{"amd64", "", "x86_64"},
	{"arm", "", "arm"},
	{"arm64", "", "aarch64"},
	{"loongarch64", "loong64", "loongarch64"},
	{"mips", "", "mips"},
	{"mipsel", "mipsle", "mipsel"},
	{"mips64", "", "mips64"},
	{"mipsel64", "mips64le", "mipsel64"},
	{"mips64n32", "mips64p32", "mips64n32"},
	{"mips3l64n32", "mips64p32le", "mipsel64n32"},
	{"ppc", "", "ppc"},
	{"ppc64", "", "ppc64"},
	{"ppc64le", "", "ppc64le"},
	{"riscv64", "", "riscv64"},
	{"s390", "", "s390"},
	{"s390x", "", "s390x"},
}

// archNames maps every accepted name for an architecture to its native name,
// and lists names that would belong to two architectures (none should).
var archNames, archNameConflicts = func() (map[string]string, []string) {
	names := map[string]string{}
	var conflicts []string
	add := func(name, native string) {
		if name == "" {
			return
		}
		if prev, ok := names[name]; ok && prev != native {
			conflicts = append(conflicts, name)
		}
		names[name] = native
	}
	for _, a := range arches {
		add(a.native, a.native)
		add(a.goarch, a.native)
		add(a.seccomp, a.native)
	}
	return names, conflicts
}()

var (
	// uname -m prints i386, i486, i586 or i686 on 32-bit x86, whichever the CPU is.
	x86Uname = regexp.MustCompile(`^i[3-6]86$`)
	// uname -m on 32-bit ARM prints armv5tel, armv6l, armv7l or armv8l.
	armUname = regexp.MustCompile(`^armv[0-9]+[a-z]*l$`)
)

// parseArch turns a --arch value into a native name. It accepts native names,
// Go names, libseccomp names and uname -m values, in any case, so that
// --arch "$(uname -m)" works. uname -m cannot tell endianness, so mips and
// mips64 mean the big-endian architectures.
func parseArch(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	if native, ok := archNames[n]; ok {
		return native, nil
	}
	switch {
	case x86Uname.MatchString(n):
		return "x86", nil
	case armUname.MatchString(n):
		return "arm", nil
	}
	var known []string
	for _, a := range arches {
		known = append(known, a.native)
	}
	slices.Sort(known)
	return "", fmt.Errorf("unknown architecture %q, want one of %s, or a Go, libseccomp or uname -m name such as x86_64, aarch64, i686, armv7l",
		s, strings.Join(known, ", "))
}

// seccompName returns the @arch name of a native architecture, or "".
func seccompName(native string) string {
	for _, a := range arches {
		if a.native == native {
			return a.seccomp
		}
	}
	return ""
}

// isCondArch reports whether name is one that arch: conditions can sensibly
// use: a native name, or x32, which profiles name although no Go host has it.
func isCondArch(name string) bool {
	return name == "x32" || slices.ContainsFunc(arches, func(a arch) bool { return a.native == name })
}

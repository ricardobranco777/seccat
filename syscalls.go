// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	_ "embed"
	"encoding/csv"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// syscallsCSV is libseccomp's syscall table (see third_party/libseccomp/README):
// a header row, then one row per syscall with a number and a kernel-version
// column for each architecture. PNR means not defined on that architecture.
//
//go:embed third_party/libseccomp/syscalls.csv
var syscallsCSV string

type syscallTable struct {
	byArch map[string][]string // libseccomp arch name -> sorted syscall names defined on it
	all    map[string]bool     // names defined on at least one architecture
}

// loadSyscalls parses the embedded table once. It panics if the embedded file
// is malformed; TestSyscallTable guards against ever shipping one.
var loadSyscalls = sync.OnceValue(func() *syscallTable {
	t, err := parseSyscalls(syscallsCSV)
	if err != nil {
		panic("syscalls.csv: " + err.Error())
	}
	return t
})

func parseSyscalls(data string) (*syscallTable, error) {
	records, err := csv.NewReader(strings.NewReader(data)).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 || !strings.HasPrefix(records[0][0], "#syscall") || len(records[0])%2 != 1 {
		return nil, fmt.Errorf("unexpected header")
	}
	var archs []string
	for i := 1; i < len(records[0]); i += 2 {
		archs = append(archs, records[0][i])
	}
	t := &syscallTable{byArch: map[string][]string{}, all: map[string]bool{}}
	for n, rec := range records[1:] {
		name := rec[0]
		for i, arch := range archs {
			switch v := rec[1+2*i]; {
			case v == "PNR":
			case isNumber(v):
				t.byArch[arch] = append(t.byArch[arch], name)
				t.all[name] = true
			default:
				return nil, fmt.Errorf("row %d (%s): bad number %q for %s", n+2, name, v, arch)
			}
		}
	}
	for _, names := range t.byArch {
		slices.Sort(names)
	}
	return t, nil
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// csvOverrides are the @arch names that libseccomp resolves with another
// architecture's numbers (little-endian variants share their big-endian table).
var csvOverrides = map[string]string{
	"mipsel":      "mips",
	"mipsel64":    "mips64",
	"mipsel64n32": "mips64n32",
	"ppc64le":     "ppc64",
}

// syscallNames lists the syscalls defined on a native architecture, sorted.
func syscallNames(native string) ([]string, error) {
	seccomp := seccompName(native)
	if o, ok := csvOverrides[seccomp]; ok {
		seccomp = o
	}
	names := loadSyscalls().byArch[seccomp]
	if names == nil {
		return nil, fmt.Errorf("no syscall table for %s", native)
	}
	return names, nil
}

// knownSyscall reports whether libseccomp's table defines name on any architecture.
func knownSyscall(name string) bool { return loadSyscalls().all[name] }

// AddDefaults adds a rule with the default action for every syscall in names
// that has no rule left, so that profiles with different defaults compare
// syscall by syscall. Syscalls that keep conditional rules are left alone: their
// fallback is the @default line.
func (d *Doc) AddDefaults(names []string) *Doc {
	out := *d
	out.Rules = slices.Clone(d.Rules)
	have := map[string]bool{}
	for _, r := range d.Rules {
		have[r.Name] = true
	}
	for _, n := range names {
		if !have[n] {
			out.Rules = append(out.Rules, Rule{Name: n, Action: d.Default})
		}
	}
	return &out
}

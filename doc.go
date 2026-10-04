// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Doc is the in-memory form of the text format: profile-wide settings plus
// one Rule per syscall name per JSON entry.
type Doc struct {
	Default          Action
	Arch             []ArchLine
	Architectures    []string
	Flags            []string
	ListenerPath     string
	ListenerMetadata string
	Rules            []Rule
}

// ArchLine is an @arch header: a native architecture and its sub-architectures.
type ArchLine struct {
	Arch string
	Subs []string
}

// Action is a seccomp action without the SCMP_ACT_ prefix. Ret is nil when the
// JSON had no errnoRet (the profile default applies).
type Action struct {
	Name string
	Ret  *uint
}

// Rule is one syscall under one set of conditions. Several rules for the same
// syscall are alternatives; the conditions of a single rule are ANDed.
type Rule struct {
	Name    string
	Action  Action
	Conds   Conds
	Comment string
}

// Conds are the conditions of a rule. Cap, arch and kernel names keep the
// vocabulary of the JSON (caps without the CAP_ prefix, arches as GOARCH names).
type Conds struct {
	Args      []ArgCond
	Caps      []string // all required (includes.caps)
	NotCaps   []string // none may be present (excludes.caps)
	Arches    []string // any of (includes.arches)
	NotArches []string // none of (excludes.arches)
	KernelGE  string   // includes.minKernel
	KernelLT  string   // excludes.minKernel
}

// ArgCond compares syscall argument Index. Op is the text operator: one of
// == != < <= > >= or & (masked equality: arg&Value == ValueTwo).
type ArgCond struct {
	Index    uint
	Op       string
	Value    uint64
	ValueTwo uint64
}

const (
	actPrefix  = "SCMP_ACT_"
	archPrefix = "SCMP_ARCH_"
	capPrefix  = "CAP_"
)

var opSymbols = map[string]string{
	"SCMP_CMP_EQ":        "==",
	"SCMP_CMP_NE":        "!=",
	"SCMP_CMP_LT":        "<",
	"SCMP_CMP_LE":        "<=",
	"SCMP_CMP_GT":        ">",
	"SCMP_CMP_GE":        ">=",
	"SCMP_CMP_MASKED_EQ": "&",
}

func actionFromJSON(name string, ret *uint) Action {
	return Action{Name: strings.TrimPrefix(name, actPrefix), Ret: ret}
}

func archFromJSON(s string) string { return strings.ToLower(strings.TrimPrefix(s, archPrefix)) }

func archesFromJSON(l []string) []string {
	return slices.Collect(func(yield func(string) bool) {
		for _, s := range l {
			if !yield(archFromJSON(s)) {
				return
			}
		}
	})
}

func capFromJSON(s string) string { return strings.TrimPrefix(strings.ToUpper(s), capPrefix) }

// sortedCaps returns normalized, sorted cap names (the lists have set semantics).
func sortedCaps(l []string) []string {
	out := make([]string, len(l))
	for i, c := range l {
		out[i] = capFromJSON(c)
	}
	slices.Sort(out)
	return out
}

func sortedCopy(l []string) []string {
	out := slices.Clone(l)
	slices.Sort(out)
	return out
}

// resolveErrno applies Podman's rule: the errno string, a name or a number,
// takes precedence over the obsolete errnoRet.
func resolveErrno(errno string, ret *uint) (*uint, error) {
	if errno == "" {
		return ret, nil
	}
	n, err := parseActionRet(errno)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// NewDoc converts a validated profile to its text-format form.
func NewDoc(p *Profile) (*Doc, error) {
	ret, err := resolveErrno(p.DefaultErrno, p.DefaultErrnoRet)
	if err != nil {
		return nil, fmt.Errorf("defaultErrno: %w", err)
	}
	d := &Doc{
		Default:          actionFromJSON(p.DefaultAction, ret),
		Architectures:    archesFromJSON(p.Architectures),
		Flags:            p.Flags,
		ListenerPath:     p.ListenerPath,
		ListenerMetadata: p.ListenerMetadata,
	}
	for _, a := range p.ArchMap {
		d.Arch = append(d.Arch, ArchLine{archFromJSON(a.Architecture), archesFromJSON(a.SubArchitecture)})
	}
	for i := range p.Syscalls {
		e := &p.Syscalls[i]
		ret, err := resolveErrno(e.Errno, e.ErrnoRet)
		if err != nil {
			return nil, fmt.Errorf("syscalls[%d].errno: %w", i, err)
		}
		base := Rule{
			Action:  actionFromJSON(e.Action, ret),
			Comment: e.Comment,
			Conds:   condsFromEntry(e),
		}
		for _, name := range e.AllNames() {
			r := base
			r.Name = name
			d.Rules = append(d.Rules, r)
		}
	}
	return d, nil
}

func condsFromEntry(e *Entry) Conds {
	var c Conds
	for _, a := range e.Args {
		c.Args = append(c.Args, ArgCond{a.Index, opSymbols[a.Op], a.Value, a.ValueTwo})
	}
	slices.SortStableFunc(c.Args, func(a, b ArgCond) int { return cmp.Compare(a.Index, b.Index) })
	if f := e.Includes; f != nil {
		c.Caps = sortedCaps(f.Caps)
		c.Arches = sortedCopy(f.Arches)
		if f.MinKernel != nil {
			c.KernelGE = *f.MinKernel
		}
	}
	if f := e.Excludes; f != nil {
		c.NotCaps = sortedCaps(f.Caps)
		c.NotArches = sortedCopy(f.Arches)
		if f.MinKernel != nil {
			c.KernelLT = *f.MinKernel
		}
	}
	return c
}

// @arch and @architectures names accepted without a warning are libseccomp's;
// arch: conditions are checked by isCondArch.
var (
	knownSeccompArches = []string{
		"aarch64", "arm", "loongarch64", "mips", "mips64", "mips64n32", "mipsel", "mipsel64",
		"mipsel64n32", "parisc", "parisc64", "ppc", "ppc64", "ppc64le", "riscv64", "s390",
		"s390x", "sh", "sheb", "x32", "x86", "x86_64",
	}
)

// Check reports names that are probably typos: syscalls, capabilities and
// architectures the tool does not know. A syscall is known if libseccomp's table
// defines it on any architecture. They are warnings, not errors, because a newer
// kernel adds all three. The result is sorted, one line per distinct problem.
func (d *Doc) Check() []string {
	users := map[string][]string{} // problem -> syscalls it appears in
	add := func(problem, syscall string) {
		if !slices.Contains(users[problem], syscall) {
			users[problem] = append(users[problem], syscall)
		}
	}
	unknownSyscalls := map[string]bool{}
	for _, r := range d.Rules {
		if !knownSyscall(r.Name) {
			unknownSyscalls[r.Name] = true
		}
		c := &r.Conds
		for _, name := range slices.Concat(c.Caps, c.NotCaps) {
			if !slices.Contains(allCaps, name) {
				add("unknown capability "+name, r.Name)
			}
		}
		for _, name := range slices.Concat(c.Arches, c.NotArches) {
			if !isCondArch(name) {
				add("unknown architecture "+name+" in arch condition", r.Name)
			}
		}
	}
	var out []string
	for name := range unknownSyscalls {
		out = append(out, "unknown syscall "+name)
	}
	for problem, names := range users {
		shown := names
		if len(shown) > 3 {
			shown = append(slices.Clone(names[:3]), fmt.Sprintf("and %d more", len(names)-3))
		}
		out = append(out, fmt.Sprintf("%s (%s)", problem, strings.Join(shown, ", ")))
	}
	header := func(kind string, names []string) {
		for _, name := range names {
			if !slices.Contains(knownSeccompArches, name) {
				out = append(out, fmt.Sprintf("unknown architecture %s in %s", name, kind))
			}
		}
	}
	for _, a := range d.Arch {
		header("@arch", slices.Concat([]string{a.Arch}, a.Subs))
	}
	header("@architectures", d.Architectures)
	slices.Sort(out)
	return slices.Compact(out)
}

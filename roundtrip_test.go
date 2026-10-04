// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The functions below describe what a profile says, computed straight from the
// JSON structs. They share nothing with the text format (Doc, Rule, formatting,
// parsing), so a field the text model drops or mangles shows up as a difference
// between the original profile and the one that went through text and back.

// entryFact is one syscall name under one entry: everything that can change
// what the entry does, order-independent. With conds, the includes/excludes
// filters are part of it; without, they are assumed already applied.
func entryFact(name string, e *Entry, conds bool) string {
	ret := "-"
	if e.Errno != "" {
		n, _ := parseActionRet(e.Errno) // Podman: the string wins over errnoRet
		ret = strconv.Itoa(int(n))
	} else if e.ErrnoRet != nil {
		ret = strconv.Itoa(int(*e.ErrnoRet))
	}
	var args []string
	for _, a := range e.Args {
		two := uint64(0)
		if a.Op == "SCMP_CMP_MASKED_EQ" { // valueTwo means nothing for the other operators
			two = a.ValueTwo
		}
		args = append(args, fmt.Sprintf("arg%d %s %d/%d", a.Index, a.Op, a.Value, two))
	}
	slices.Sort(args)
	fact := fmt.Sprintf("%s | %s | errno %s | %s | %q", name, e.Action, ret, strings.Join(args, ", "), e.Comment)
	if conds {
		fact += " | " + filterFact("includes", e.Includes) + " | " + filterFact("excludes", e.Excludes)
	}
	return fact
}

// filterFact describes a filter. A missing filter and an empty one ("includes": {},
// which Podman's profile writes on every entry) say the same thing.
func filterFact(label string, f *Filter) string {
	if f == nil || (len(f.Caps) == 0 && len(f.Arches) == 0 && f.MinKernel == nil) {
		return label + " none"
	}
	var caps []string
	for _, c := range f.Caps {
		caps = append(caps, strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
	}
	slices.Sort(caps)
	kernel := "-"
	if f.MinKernel != nil {
		kernel = *f.MinKernel
	}
	return fmt.Sprintf("%s caps=%v arches=%v kernel=%s", label, caps, sortedCopy(f.Arches), kernel)
}

// ruleFacts counts the entry facts of the entries that keep selects.
func ruleFacts(p *Profile, keep func(*Entry) bool, conds bool) map[string]int {
	facts := map[string]int{}
	for i := range p.Syscalls {
		e := &p.Syscalls[i]
		if !keep(e) {
			continue
		}
		for _, name := range e.AllNames() {
			facts[entryFact(name, e, conds)]++
		}
	}
	return facts
}

// headerFact covers everything outside syscalls[]. Order is kept where the
// format keeps it (archMap, flags).
func headerFact(p *Profile) string {
	ret := "-"
	if p.DefaultErrno != "" {
		n, _ := parseActionRet(p.DefaultErrno)
		ret = strconv.Itoa(int(n))
	} else if p.DefaultErrnoRet != nil {
		ret = strconv.Itoa(int(*p.DefaultErrnoRet))
	}
	var arch []string
	for _, a := range p.ArchMap {
		arch = append(arch, fmt.Sprintf("%s%v", a.Architecture, a.SubArchitecture))
	}
	return fmt.Sprintf("default %s errno %s | archMap %v | architectures %v | flags %v | listener %q %q",
		p.DefaultAction, ret, arch, p.Architectures, p.Flags, p.ListenerPath, p.ListenerMetadata)
}

// viaText sends a profile file through seccat as a user would: JSON to text,
// then text back to JSON.
func viaText(t *testing.T, path string) (original, roundTripped *Profile) {
	t.Helper()
	original, _ = loadFile(t, path)
	var text, js, errb strings.Builder
	if code := run([]string{path}, nil, &text, &errb); code != 0 {
		t.Fatalf("%s to text: exit %d: %s", path, code, errb.String())
	}
	if code := run([]string{"-j"}, strings.NewReader(text.String()), &js, &errb); code != 0 {
		t.Fatalf("%s to JSON: exit %d: %s", path, code, errb.String())
	}
	roundTripped, warnings, err := LoadProfile(strings.NewReader(js.String()))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("%s: round-tripped JSON does not load cleanly: %v %v", path, err, warnings)
	}
	return original, roundTripped
}

func diffFacts(a, b map[string]int) (onlyA, onlyB []string) {
	for k, n := range a {
		if b[k] != n {
			onlyA = append(onlyA, fmt.Sprintf("%dx %s", n, k))
		}
	}
	for k, n := range b {
		if a[k] != n {
			onlyB = append(onlyB, fmt.Sprintf("%dx %s", n, k))
		}
	}
	slices.Sort(onlyA)
	slices.Sort(onlyB)
	return onlyA, onlyB
}

// sameBehavior compares two profiles: the header, every entry with its
// conditions, and the rules that survive moby's filtering for each combination
// of capability set, architecture and kernel (what the runtime receives). It
// returns after max problems if max is above zero, and reports all otherwise.
func sameBehavior(a, b *Profile, max int) []string {
	var problems []string
	full := func() bool { return max > 0 && len(problems) >= max }
	if x, y := headerFact(a), headerFact(b); x != y {
		problems = append(problems, "header differs:\n  "+x+"\n  "+y)
	}
	if full() {
		return problems
	}
	all := func(*Entry) bool { return true }
	if onlyA, onlyB := diffFacts(ruleFacts(a, all, true), ruleFacts(b, all, true)); len(onlyA)+len(onlyB) > 0 {
		problems = append(problems, fmt.Sprintf("entries differ: only in first %v, only in second %v", onlyA, onlyB))
	}
	if full() {
		return problems
	}
	for _, preset := range []string{"docker", "podman", "none", "all", "docker,SYS_ADMIN"} {
		caps, _ := parseCaps(preset)
		for _, arch := range []string{"amd64", "arm64", "s390x", "x86"} {
			for _, kernel := range []string{"4.7", "4.8", "4.10", "6.8"} {
				ver, _ := parseVersion(kernel)
				keep := func(e *Entry) bool { return refKeep(e, caps, arch, ver) }
				if onlyA, onlyB := diffFacts(ruleFacts(a, keep, false), ruleFacts(b, keep, false)); len(onlyA)+len(onlyB) > 0 {
					problems = append(problems, fmt.Sprintf("%s/%s/%s: filtered rules differ: %v vs %v", preset, arch, kernel, onlyA, onlyB))
					if full() {
						return problems
					}
				}
			}
		}
	}
	return problems
}

func TestRoundTripKeepsBehavior(t *testing.T) {
	for _, name := range []string{"docker", "podman"} {
		original, roundTripped := viaText(t, "testdata/"+name+".json")
		for _, problem := range sameBehavior(original, roundTripped, 0) {
			t.Errorf("%s: %s", name, problem)
		}
	}
}

// TestSameBehaviorDetectsChanges checks that the comparison above can fail:
// each change to the round-tripped profile must be reported.
func TestSameBehaviorDetectsChanges(t *testing.T) {
	changes := map[string]func(p *Profile){
		"default action":  func(p *Profile) { p.DefaultAction = "SCMP_ACT_ALLOW" },
		"default errno":   func(p *Profile) { n := uint(7); p.DefaultErrnoRet = &n },
		"archMap":         func(p *Profile) { p.ArchMap = p.ArchMap[1:] },
		"flags":           func(p *Profile) { p.Flags = append(p.Flags, "SECCOMP_FILTER_FLAG_LOG") },
		"dropped entry":   func(p *Profile) { p.Syscalls = p.Syscalls[1:] },
		"dropped name":    func(p *Profile) { p.Syscalls[0].Names = p.Syscalls[0].Names[1:] },
		"changed action":  func(p *Profile) { p.Syscalls[0].Action = "SCMP_ACT_KILL" },
		"changed errno":   func(p *Profile) { n := uint(99); p.Syscalls[0].ErrnoRet = &n },
		"added cap":       func(p *Profile) { p.Syscalls[0].Includes = &Filter{Caps: []string{"CAP_SYS_ADMIN"}} },
		"changed comment": func(p *Profile) { p.Syscalls[0].Comment = "x" },
		"changed arg": func(p *Profile) {
			for i := range p.Syscalls {
				if len(p.Syscalls[i].Args) > 0 {
					p.Syscalls[i].Args[0].Value++
					return
				}
			}
		},
		"changed arg op": func(p *Profile) {
			for i := range p.Syscalls {
				if len(p.Syscalls[i].Args) > 0 {
					p.Syscalls[i].Args[0].Op = "SCMP_CMP_NE"
					return
				}
			}
		},
		"changed min kernel": func(p *Profile) {
			for i := range p.Syscalls {
				if f := p.Syscalls[i].Includes; f != nil && f.MinKernel != nil {
					v := "9.9"
					f.MinKernel = &v
					return
				}
			}
		},
	}
	for what, change := range changes {
		original, roundTripped := viaText(t, "testdata/docker.json")
		change(roundTripped)
		if len(sameBehavior(original, roundTripped, 1)) == 0 {
			t.Errorf("a change of %s went unnoticed", what)
		}
	}
}

// TestRoundTripWithJq runs the shell check from the README: contrib/normalize.jq
// on the original and on the round-tripped JSON must give the same lines.
func TestRoundTripWithJq(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not installed")
	}
	normalize := func(path string) []string {
		t.Helper()
		out, err := exec.Command(jq, "-S", "-c", "-f", "contrib/normalize.jq", path).Output()
		if err != nil {
			t.Fatalf("jq on %s: %v", path, err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		slices.Sort(lines)
		return lines
	}
	for _, f := range []struct {
		name     string
		minLines int
	}{{"docker", 400}, {"podman", 400}, {"log-only", 1}, {"oci-seccomp", 15}} {
		name := f.name
		path := "testdata/" + name + ".json"
		var text, js, errb strings.Builder
		if run([]string{path}, nil, &text, &errb) != 0 || run([]string{"-j"}, strings.NewReader(text.String()), &js, &errb) != 0 {
			t.Fatal(errb.String())
		}
		roundTripped := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(roundTripped, []byte(js.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		a, b := normalize(path), normalize(roundTripped)
		if len(a) < f.minLines {
			t.Fatalf("%s: only %d normalized lines, the filter is probably broken", name, len(a))
		}
		if !slices.Equal(a, b) {
			t.Errorf("%s: normalized round trip differs (%d vs %d lines)", name, len(a), len(b))
		}
	}
}

// A profile may be nothing but a default action, as in the Kubernetes examples:
// there is no syscalls key at all.
func TestDefaultActionOnly(t *testing.T) {
	var out, errb strings.Builder
	if code := run([]string{"testdata/log-only.json"}, nil, &out, &errb); code != 0 || errb.Len() != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if out.String() != "@default\tLOG\n" {
		t.Errorf("got %q", out.String())
	}
	original, roundTripped := viaText(t, "testdata/log-only.json")
	for _, problem := range sameBehavior(original, roundTripped, 0) {
		t.Error(problem)
	}
}

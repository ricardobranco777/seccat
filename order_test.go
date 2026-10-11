// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"slices"
	"strings"
	"testing"
)

// libseccomp can pick another action for the same call depending on the order
// in which a syscall's rules were added, so seccat keeps that order.

const orderProfile = `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["socket"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
     "args": [{"index": 0, "value": 4294967295, "valueTwo": 40, "op": "SCMP_CMP_MASKED_EQ"}]},
    {"names": ["socket", "bind"], "action": "SCMP_ACT_ALLOW",
     "args": [{"index": 0, "value": 40, "op": "SCMP_CMP_NE"}]}
  ]
}`

func textOf(t *testing.T, profile string) []string {
	t.Helper()
	p, _, err := LoadProfile(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(docText(t, d)), "\n")
}

func TestTextKeepsRuleOrderOfASyscall(t *testing.T) {
	got := textOf(t, orderProfile)
	want := []string{
		"@default\tERRNO(EPERM)",
		"bind\tALLOW\targ0!=40",
		"socket\tERRNO(EPERM)\targ0&0xffffffff==40",
		"socket\tALLOW\targ0!=40",
	}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	// Names are sorted; the two socket rules keep the order of the profile.
	var socket []string
	for _, l := range got {
		if strings.HasPrefix(l, "socket\t") {
			socket = append(socket, l)
		}
	}
	if len(socket) != 2 || !strings.Contains(socket[0], "ERRNO") || !strings.Contains(socket[1], "ALLOW") {
		t.Errorf("socket rules out of order: %q", socket)
	}
	if !strings.HasPrefix(got[1], "bind\t") {
		t.Errorf("syscalls not sorted by name: %q", got)
	}

	// The other way round in the profile gives the other order in the text.
	swapped := `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["socket"], "action": "SCMP_ACT_ALLOW",
     "args": [{"index": 0, "value": 40, "op": "SCMP_CMP_NE"}]},
    {"names": ["socket"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
     "args": [{"index": 0, "value": 4294967295, "valueTwo": 40, "op": "SCMP_CMP_MASKED_EQ"}]}
  ]
}`
	got = textOf(t, swapped)
	if !strings.Contains(got[1], "ALLOW") || !strings.Contains(got[2], "ERRNO") {
		t.Errorf("swapped profile: %q", got)
	}
}

// Rules that differ only in name are merged into one entry, but never so that
// the rules of one syscall change places: x has K2 before K1 here, although a
// has K1.
func TestJSONKeepsRuleOrderOfASyscall(t *testing.T) {
	text := "@default\tERRNO(EPERM)\n" +
		"a\tALLOW\n" +
		"x\tERRNO(EPERM)\targ0==1\n" +
		"x\tALLOW\n"
	d, err := ParseText(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	p := d.Profile()
	var got []string
	for _, e := range p.Syscalls {
		for _, n := range e.AllNames() {
			if n == "x" {
				got = append(got, e.Action)
			}
		}
	}
	if want := []string{"SCMP_ACT_ERRNO", "SCMP_ACT_ALLOW"}; !slices.Equal(got, want) {
		t.Errorf("rules of x: got %v, want %v", got, want)
	}
	back, err := NewDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	var xs []string
	for l := range strings.SplitSeq(docText(t, back), "\n") {
		if strings.HasPrefix(l, "x\t") {
			xs = append(xs, l)
		}
	}
	if want := []string{"x\tERRNO(EPERM)\targ0==1", "x\tALLOW"}; !slices.Equal(xs, want) {
		t.Errorf("text after the round trip: got %q, want %q", xs, want)
	}
}

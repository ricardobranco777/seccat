// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSymbolRoundTrip(t *testing.T) {
	// Each condition renders as shown and parses back to the same value.
	tests := []struct{ name, syscall, cond, want string }{
		{"af name", "socket", "arg0==16", "arg0==AF_NETLINK"},
		{"af ne", "socket", "arg0!=1", "arg0!=AF_UNIX"},
		{"af unnamed stays decimal", "socket", "arg0==99", "arg0==99"},
		{"ordering stays numeric", "socket", "arg0<3", "arg0<3"},
		{"netlink needs AF_NETLINK", "socket", "arg0==16 && arg2==9", "arg0==AF_NETLINK && arg2==NETLINK_AUDIT"},
		{"no netlink names without context", "socket", "arg0==2 && arg2==9", "arg0==AF_INET && arg2==9"},
		{"persona base", "personality", "arg0==8", "arg0==PER_LINUX32"},
		{"persona zero", "personality", "arg0==0", "arg0==PER_LINUX"},
		{"persona combo", "personality", "arg0==131080", "arg0==PER_LINUX32|UNAME26"},
		{"persona unnamed bits hex", "personality", "arg0==4294967295", "arg0==0xffffffff"},
		{"persona unnamed bit alone", "personality", "arg0==4", "arg0==0x4"},
		{"clone mask", "clone", "arg0&0x7e020000==0", "arg0&(CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET)==0"},
		{"clone single flag mask", "clone", "arg0&0x20000==0", "arg0&CLONE_NEWNS==0"},
		{"clone mask unnamed bit", "clone", "arg0&0x1==0", "arg0&0x1==0"},
		{"clone arg1 (s390)", "clone", "arg1&0x20000==0", "arg1&CLONE_NEWNS==0"},
		{"no table: decimal and hex mask", "read", "arg0==16 && arg1&0xff==3", "arg0==16 && arg1&0xff==3"},
	}
	for _, tt := range tests {
		d := mustParse(t, "@default\tKILL\n"+tt.syscall+"\tALLOW\t"+tt.cond+"\n")
		want := "@default\tKILL\n" + tt.syscall + "\tALLOW\t" + tt.want + "\n"
		got := docText(t, d)
		if got != want {
			t.Errorf("%s: got %q, want %q", tt.name, got, want)
			continue
		}
		// The rendered form must mean the same thing as the original.
		d2 := mustParse(t, got)
		if a, b := d.Rules[0].Conds.Args, d2.Rules[0].Conds.Args; len(a) != len(b) {
			t.Errorf("%s: arg count changed", tt.name)
		} else {
			for i := range a {
				if a[i] != b[i] {
					t.Errorf("%s: arg %d changed: %+v -> %+v", tt.name, i, a[i], b[i])
				}
			}
		}
	}
}

func TestSymbolInput(t *testing.T) {
	// Aliases, parentheses and mixed names/numbers are accepted on input.
	tests := []struct{ cond, want string }{
		{"arg0==AF_LOCAL", "arg0==AF_UNIX"},
		{"arg0==AF_ROUTE", "arg0==AF_NETLINK"},
		{"arg0==(AF_INET)", "arg0==AF_INET"},
		{"arg0&(CLONE_NEWNS|0x2000000)==0", "arg0&(CLONE_NEWNS|CLONE_NEWCGROUP)==0"},
	}
	for _, tt := range tests {
		sc := "socket"
		if strings.HasPrefix(tt.cond, "arg0&") {
			sc = "clone"
		}
		got := docText(t, mustParse(t, "@default\tKILL\n"+sc+"\tALLOW\t"+tt.cond+"\n"))
		if want := "@default\tKILL\n" + sc + "\tALLOW\t" + tt.want + "\n"; got != want {
			t.Errorf("%s: got %q, want %q", tt.cond, got, want)
		}
	}
	for _, bad := range []string{"arg0==AF_BOGUS", "arg0==(AF_INET", "arg0==AF_INET|"} {
		if _, err := ParseText(strings.NewReader("@default\tKILL\nsocket\tALLOW\t" + bad + "\n")); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
	// Names only resolve where a table applies.
	if _, err := ParseText(strings.NewReader("@default\tKILL\nread\tALLOW\targ0==AF_INET\n")); err == nil {
		t.Error("AF_INET accepted for read")
	}
}

func TestTablesWellFormed(t *testing.T) {
	for name, tbl := range map[string]*symTable{
		"af": afTable, "netlink": netlinkTable, "persona": personaTable, "clone": cloneTable,
	} {
		seen := map[uint64]string{}
		for _, s := range tbl.syms {
			if prev, dup := seen[s.value]; dup {
				t.Errorf("%s: %s and %s share value %#x", name, prev, s.name, s.value)
			}
			seen[s.value] = s.name
		}
	}
	if afTable.byName["AF_LOCAL"] != unix.AF_UNIX {
		t.Error("alias AF_LOCAL does not resolve")
	}
}

func TestErrnoAliases(t *testing.T) {
	// Aliases are accepted on input and written under the canonical name.
	tests := []struct{ in, want string }{
		{"ERRNO(EWOULDBLOCK)", "ERRNO(EAGAIN)"},
		{"ERRNO(EAGAIN)", "ERRNO(EAGAIN)"},
		{"ERRNO(EDEADLOCK)", "ERRNO(EDEADLK)"},
		{"ERRNO(EOPNOTSUPP)", "ERRNO(EOPNOTSUPP)"},
		{"ERRNO(ENOTSUP)", "ERRNO(EOPNOTSUPP)"},
		{"ERRNO(EUCLEAN)", "ERRNO(EUCLEAN)"},
		{"ERRNO(EFSCORRUPTED)", "ERRNO(EUCLEAN)"},
		{"ERRNO(EFSBADCRC)", "ERRNO(EBADMSG)"},
		{"ERRNO(4000)", "ERRNO(4000)"},
	}
	for _, tt := range tests {
		got := docText(t, mustParse(t, "@default\tKILL\nx\t"+tt.in+"\n"))
		if want := "@default\tKILL\nx\t" + tt.want + "\n"; got != want {
			t.Errorf("%s: got %q, want %q", tt.in, got, want)
		}
	}
	// Every alias must resolve, so a typo in the table fails here.
	for alias, name := range errnoAliases {
		if errnoByName[alias] == 0 || errnoByName[alias] != errnoByName[name] {
			t.Errorf("alias %s -> %s does not resolve", alias, name)
		}
	}
	if _, err := ParseText(strings.NewReader("@default\tKILL\nx\tERRNO(EBOGUS)\n")); err == nil {
		t.Error("unknown errno accepted")
	}
}

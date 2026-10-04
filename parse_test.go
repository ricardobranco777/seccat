// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func docText(t *testing.T, d *Doc) string {
	t.Helper()
	var buf bytes.Buffer
	if err := d.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func mustParse(t *testing.T, text string) *Doc {
	t.Helper()
	d, err := ParseText(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseText: %v\n%s", err, text)
	}
	return d
}

func TestRoundTrip(t *testing.T) {
	for _, name := range []string{"docker", "podman"} {
		text := formatFile(t, "testdata/"+name+".json")
		d := mustParse(t, text)
		if got := docText(t, d); got != text {
			t.Errorf("%s: text -> doc -> text changed the output", name)
		}

		// Through JSON: the encoded profile must load, validate and render identically.
		var buf bytes.Buffer
		if err := d.Profile().Encode(&buf); err != nil {
			t.Fatal(err)
		}
		p, warnings, err := LoadProfile(&buf)
		if err != nil || len(warnings) != 0 {
			t.Fatalf("%s: reload: %v %v", name, err, warnings)
		}
		d2, err := NewDoc(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := docText(t, d2); got != text {
			t.Errorf("%s: text -> JSON -> text changed the output", name)
		}
	}
}

func TestDuplicatesKept(t *testing.T) {
	// "a" appears twice as ALLOW and once as ERRNO; "b" once as ALLOW.
	p := mustParse(t, "@default\tERRNO\na\tALLOW\na\tALLOW\nb\tALLOW\na\tERRNO(EPERM)\n").Profile()
	var allow [][]string
	for _, e := range p.Syscalls {
		if e.Action == "SCMP_ACT_ALLOW" {
			allow = append(allow, e.Names)
		}
	}
	if len(p.Syscalls) != 3 || len(allow) != 2 || len(allow[0]) != 2 || len(allow[1]) != 1 {
		t.Errorf("got %d entries, allow groups %v", len(p.Syscalls), allow)
	}
}

func TestCommentAndEscapes(t *testing.T) {
	text := "@default\tERRNO\n@listenerPath\t/tmp/a\\tb\nx\tALLOW\t# a\\tb\\\\c\\nd\ny\tALLOW\tcap:SYS_ADMIN\t# note\n"
	d := mustParse(t, text)
	if d.Rules[0].Comment != "a\tb\\c\nd" || d.ListenerPath != "/tmp/a\tb" {
		t.Errorf("bad unescape: %q %q", d.Rules[0].Comment, d.ListenerPath)
	}
	if got := docText(t, d); got != text {
		t.Errorf("got:\n%s\nwant:\n%s", got, text)
	}
}

func TestInputLeniency(t *testing.T) {
	// Comments, blank lines, any condition order, CAP_ prefix, and 0x/decimal numbers.
	d := mustParse(t, "# hi\n\n@default\tKILL\nx\tALLOW\t!arch:s390 && kernel>=4.8 && cap:CAP_bpf && arg1<=0x10\n")
	want := "@default\tKILL\nx\tALLOW\targ1<=16 && cap:BPF && !arch:s390 && kernel>=4.8\n"
	if got := docText(t, d); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestErrnoStringsResolved(t *testing.T) {
	in := `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrno":"ENOSYS",
	"syscalls":[{"names":["a"],"action":"SCMP_ACT_ERRNO","errno":"EPERM"},
	            {"names":["b"],"action":"SCMP_ACT_ERRNO","errno":"22"}]}`
	p, _, err := LoadProfile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	want := "@default\tERRNO(ENOSYS)\na\tERRNO(EPERM)\nb\tERRNO(EINVAL)\n"
	if got := docText(t, d); got != want {
		t.Errorf("got %q want %q", got, want)
	}
	p.Syscalls[0].Errno = "EBOGUS"
	if _, err := NewDoc(p); err == nil || !strings.Contains(err.Error(), "syscalls[0].errno") {
		t.Errorf("want errno error, got %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"no default", "a\tALLOW\n", "missing @default"},
		{"dup default", "@default\tKILL\n@default\tKILL\n", "line 2: duplicate @default"},
		{"unknown header", "@default\tKILL\n@bogus\tx\n", "line 2: unknown header"},
		{"short rule", "@default\tKILL\nlonely\n", "line 2: want NAME"},
		{"bad action", "@default\tKILL\na\tNOPE\n", `line 2: unknown action "NOPE"`},
		{"bad errno", "@default\tKILL\na\tERRNO(EBOGUS)\n", "unknown errno"},
		{"unclosed paren", "@default\tKILL\na\tERRNO(EPERM\n", "malformed action"},
		{"bad condition", "@default\tKILL\na\tALLOW\tbogus\n", `condition "bogus"`},
		{"bad arg op", "@default\tKILL\na\tALLOW\targ0=1\n", "malformed argument"},
		{"bad arg index", "@default\tKILL\na\tALLOW\targ6==1\n", "out of range"},
		{"bad number", "@default\tKILL\na\tALLOW\targ0==zz\n", "bad number"},
		{"mask without eq", "@default\tKILL\na\tALLOW\targ0&0xff\n", "needs =="},
		{"bad kernel", "@default\tKILL\na\tALLOW\tkernel>=4\n", "invalid kernel version"},
		{"dup arch", "@default\tKILL\na\tALLOW\tarch:a && arch:b\n", "duplicate"},
		{"bad cap", "@default\tKILL\na\tALLOW\tcap:A-B\n", "bad capability"},
		{"extra field", "@default\tKILL\na\tALLOW\tcap:A\tcap:B\n", "too many fields"},
		{"bad escape", "@default\tKILL\na\tALLOW\t# \\q\n", "unknown escape"},
	}
	for _, tt := range tests {
		_, err := ParseText(strings.NewReader(tt.in))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want containing %q", tt.name, err, tt.want)
		}
	}
}

func TestRunConvert(t *testing.T) {
	var sec, js, stderr bytes.Buffer
	if code := run([]string{"testdata/podman.json"}, nil, &sec, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if code := run([]string{"-j"}, &sec, &js, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(js.String(), `"defaultErrnoRet": 38`) {
		t.Errorf("unexpected JSON: %.200s", js.String())
	}
	if code := run([]string{"nonexistent.json"}, nil, &sec, &stderr); code != 1 {
		t.Errorf("missing file: exit %d, want 1", code)
	}
}

func TestCheck(t *testing.T) {
	for _, name := range []string{"docker", "podman"} {
		p, _ := loadFile(t, "testdata/"+name+".json")
		d, err := NewDoc(p)
		if err != nil {
			t.Fatal(err)
		}
		if w := d.Check(); len(w) != 0 {
			t.Errorf("%s: unexpected warnings %v", name, w)
		}
		if w := mustParse(t, docText(t, d)).Check(); len(w) != 0 {
			t.Errorf("%s (text): unexpected warnings %v", name, w)
		}
	}
	d := mustParse(t, "@default\tKILL\n@arch\tx99\tx86,bogus\n@architectures\tx86_64,nope\n"+
		"read\tALLOW\tcap:SYS_ADMN\n"+
		"write\tALLOW\t!cap:SYS_ADMN && cap:BPF\n"+
		"open\tALLOW\tcap:SYS_ADMN\n"+
		"close\tALLOW\tcap:SYS_ADMN\n"+
		"stat\tALLOW\tcap:SYS_ADMN\n"+
		"fstat\tALLOW\tarch:amd46,amd64 && !arch:s390x\n")
	want := []string{
		"unknown architecture amd46 in arch condition (fstat)",
		"unknown architecture bogus in @arch",
		"unknown architecture nope in @architectures",
		"unknown architecture x99 in @arch",
		"unknown capability SYS_ADMN (read, write, open, and 2 more)",
	}
	if got := d.Check(); !slices.Equal(got, want) {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRunWarnsButSucceeds(t *testing.T) {
	var out, errb bytes.Buffer
	in := strings.NewReader("@default\tKILL\nread\tALLOW\tcap:SYS_ADMN\n")
	if code := run([]string{"-j"}, in, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "warning: unknown capability SYS_ADMN (read)") || out.Len() == 0 {
		t.Errorf("stderr %q, stdout %d bytes", errb.String(), out.Len())
	}
	// JSON -> text warns too, before evaluation can drop the rule.
	out.Reset()
	errb.Reset()
	json := `{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMN"]}}]}`
	if code := run([]string{"--caps", "all"}, strings.NewReader(json), &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "unknown capability SYS_ADMN") {
		t.Errorf("no warning for a rule that evaluation drops: %q", errb.String())
	}
}

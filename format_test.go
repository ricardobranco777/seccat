// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func formatFile(t *testing.T, path string) string {
	t.Helper()
	p, _ := loadFile(t, path)
	var buf bytes.Buffer
	d, err := NewDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestGoldenFormat(t *testing.T) {
	for _, name := range []string{"docker", "podman"} {
		got := formatFile(t, "testdata/"+name+".json")
		golden := "testdata/" + name + ".sec"
		if *update {
			if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s differs from golden; run make update-golden and review the diff", name)
		}
	}
}

func TestNaturalCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"arg0==8", "arg0==10", -1},
		{"arg0==10", "arg0==8", 1},
		{"a", "a", 0},
		{"clone\tx", "clone3\tx", -1},
		{"a08", "a8", -1},
		{"a99999999999999999999999", "a100000000000000000000000", -1},
		{"ab", "abc", -1},
	}
	for _, tt := range tests {
		if got := naturalCompare(tt.a, tt.b); (got < 0) != (tt.want < 0) || (got > 0) != (tt.want > 0) {
			t.Errorf("naturalCompare(%q, %q) = %d, want sign %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestFormatEdges(t *testing.T) {
	in := `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,
	"syscalls":[
	 {"names":["b","a"],"action":"SCMP_ACT_ERRNO","errnoRet":38,"comment":"tab\there",
	  "includes":{"caps":["CAP_SYS_ADMIN","CAP_BPF"],"arches":["s390x","s390"],"minKernel":"4.8"},
	  "excludes":{"caps":["CAP_NET_RAW"],"arches":["x32"],"minKernel":"6.0"},
	  "args":[{"index":2,"op":"SCMP_CMP_GE","value":3},{"index":0,"op":"SCMP_CMP_MASKED_EQ","value":255,"valueTwo":1}]},
	 {"name":"c","action":"SCMP_ACT_TRACE","errnoRet":7},
	 {"names":["d"],"action":"SCMP_ACT_ERRNO","errnoRet":4000}]}`
	p, _, err := LoadProfile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	d, err := NewDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	want := "@default\tERRNO(EPERM)\n" +
		"a\tERRNO(ENOSYS)\targ0&0xff==1 && arg2>=3 && cap:BPF && cap:SYS_ADMIN && !cap:NET_RAW && arch:s390,s390x && !arch:x32 && kernel>=4.8 && kernel<6.0\t# tab\\there\n" +
		"b\tERRNO(ENOSYS)\targ0&0xff==1 && arg2>=3 && cap:BPF && cap:SYS_ADMIN && !cap:NET_RAW && arch:s390,s390x && !arch:x32 && kernel>=4.8 && kernel<6.0\t# tab\\there\n" +
		"c\tTRACE(7)\n" +
		"d\tERRNO(4000)\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestNumeric(t *testing.T) {
	text, _, code := runText(t, "--numeric", "--arch", "amd64", "--caps", "none", "--kernel", "6.8", "testdata/docker.json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"clone\tALLOW\targ0&0x7e020000==0\n", "personality\tALLOW\targ0==8\n", "socket\tALLOW\targ0==10\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	if regexp.MustCompile(`arg\d[^\t]*(AF_|CLONE_|PER_|NETLINK_)`).MatchString(text) {
		t.Error("a symbolic value is left")
	}
	// The numbers mean the same: both give the same symbolic text again.
	names, _, _ := runText(t, "--arch", "amd64", "--caps", "none", "--kernel", "6.8", "testdata/docker.json")
	back := func(in string) string {
		var j, out strings.Builder
		if run([]string{"--json"}, strings.NewReader(in), &j, io.Discard) != 0 ||
			run(nil, strings.NewReader(j.String()), &out, io.Discard) != 0 {
			t.Fatal("round trip failed")
		}
		return out.String()
	}
	if back(text) != back(names) {
		t.Error("numeric and symbolic text mean different things")
	}
	if _, _, code := runText(t, "--numeric", "--json"); code != 2 {
		t.Errorf("--numeric --json: exit %d, want 2", code)
	}
}

// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const ociText = "@default\tERRNO(ENOSYS)\n" +
	"@architectures\tx86_64,x86,x32\n" +
	"@flag\tSECCOMP_FILTER_FLAG_LOG\n" +
	"@listenerPath\t/run/seccomp-agent.socket\n" +
	"@listenerMetadata\texample\n" +
	"chmod\tNOTIFY\n" +
	"clone\tALLOW\targ0&(CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET)==0\n" +
	"dup3\tALLOW\targ0>2\n" +
	"exit_group\tALLOW\n" +
	"ftruncate\tALLOW\targ0==100 && arg1==1337\n" +
	"futex\tALLOW\n" +
	"getcwd\tERRNO(ENOANO)\n" +
	"mkdir\tNOTIFY\n" +
	"process_vm_writev\tERRNO(ENOANO)\targ0==1 && arg0==2\n" +
	"ptrace\tKILL_PROCESS\n" +
	"read\tALLOW\n" +
	"socket\tALLOW\targ0!=AF_NETLINK\n" +
	"socket\tALLOW\targ2&0xf00==0\n" +
	"write\tALLOW\n"

// realBundles are config.json files written by `runc spec`. It does not include
// a seccomp profile, and neither does the one `crun spec` writes.
var realBundles = []string{"testdata/runc-config.json"}

func runText(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb strings.Builder
	code = run(args, nil, &out, &errb)
	return out.String(), errb.String(), code
}

// bundleWith returns the path of a copy of a real bundle whose linux.seccomp is
// the profile in seccompPath, the way runc's own tests add one.
func bundleWith(t *testing.T, bundlePath, seccompPath string) string {
	t.Helper()
	var bundle map[string]any
	var seccomp any
	for path, dst := range map[string]any{bundlePath: &bundle, seccompPath: &seccomp} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, dst); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	linux, ok := bundle["linux"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no linux section", bundlePath)
	}
	linux["seccomp"] = seccomp
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), filepath.Base(bundlePath))
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// An OCI linux.seccomp object, and a real bundle that holds one, read like a profile.
func TestOCIInput(t *testing.T) {
	paths := []string{"testdata/oci-seccomp.json"}
	for _, bundle := range realBundles {
		paths = append(paths, bundleWith(t, bundle, "testdata/oci-seccomp.json"))
	}
	for _, path := range paths {
		out, stderr, code := runText(t, path)
		if code != 0 || stderr != "" {
			t.Fatalf("%s: exit %d, stderr %q", filepath.Base(path), code, stderr) // the rest of a bundle must not warn
		}
		if out != ociText {
			t.Errorf("%s: got\n%s\nwant\n%s", filepath.Base(path), out, ociText)
		}
	}
}

// Neither runc spec nor crun spec writes a seccomp section, so their output is a
// real bundle without a profile.
func TestRealBundlesWithoutSeccomp(t *testing.T) {
	for _, path := range realBundles {
		_, stderr, code := runText(t, path)
		if code != 1 || !strings.Contains(stderr, "no linux.seccomp section") {
			t.Errorf("%s: exit %d, stderr %q", path, code, stderr)
		}
	}
}

// OCI input has been filtered already: there are no conditions left to settle.
func TestOCIInputIgnoresEvaluationFlags(t *testing.T) {
	path := bundleWith(t, realBundles[0], "testdata/oci-seccomp.json")
	want, _, _ := runText(t, path)
	got, stderr, code := runText(t, "--caps", "docker", "--arch", "amd64", "--kernel", "6.8", path)
	if code != 0 || stderr != "" || got != want {
		t.Errorf("flags changed the output of an OCI profile: exit %d, stderr %q", code, stderr)
	}
	if out, _, code := runText(t, "--all", "--arch", "amd64", path); code != 0 || !strings.Contains(out, "\nkexec_load\tERRNO(ENOSYS)\n") {
		t.Errorf("--all on an OCI profile: exit %d", code)
	}
}

func TestOCIErrors(t *testing.T) {
	for name, tt := range map[string]struct{ in, want string }{
		"no linux":          {`{"ociVersion":"1.2.0"}`, "no linux.seccomp section"},
		"linux, no seccomp": {`{"ociVersion":"1.2.0","linux":{"namespaces":[]}}`, "no linux.seccomp section"},
		"seccomp null":      {`{"ociVersion":"1.2.0","linux":{"seccomp":null}}`, "no linux.seccomp section"},
		"linux not object":  {`{"ociVersion":"1.2.0","linux":[]}`, "linux is not an object"},
		"bad seccomp":       {`{"ociVersion":"1.2.0","linux":{"seccomp":{"defaultAction":"NOPE"}}}`, "unknown action"},
		"not an object":     {`[1,2]`, "decoding profile"},
	} {
		if _, _, err := LoadProfile(strings.NewReader(tt.in)); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want containing %q", name, err, tt.want)
		}
	}
	// Without ociVersion the input is a profile, whatever else it holds.
	if _, _, err := LoadProfile(strings.NewReader(`{"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW"}}}`)); err == nil {
		t.Error("input without ociVersion was read as config.json")
	}
}

func TestOCIWarningPaths(t *testing.T) {
	const seccomp = `"defaultAction":"SCMP_ACT_ALLOW","bogus":1,"syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","extra":2}]`
	_, bare, err := LoadProfile(strings.NewReader(`{` + seccomp + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bogus", "syscalls[0].extra"}; !slices.Equal(bare, want) {
		t.Errorf("bare: %v, want %v", bare, want)
	}
	_, inConfig, err := LoadProfile(strings.NewReader(`{"ociVersion":"1.2.0","process":{"unrelated":1},"linux":{"seccomp":{` + seccomp + `}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"linux.seccomp.bogus", "linux.seccomp.syscalls[0].extra"}; !slices.Equal(inConfig, want) {
		t.Errorf("config.json: %v, want %v", inConfig, want)
	}
}

func TestOCIRoundTrip(t *testing.T) {
	paths := []string{"testdata/oci-seccomp.json"}
	for _, bundle := range realBundles {
		paths = append(paths, bundleWith(t, bundle, "testdata/oci-seccomp.json"))
	}
	for _, path := range paths {
		original, roundTripped := viaText(t, path)
		for _, problem := range sameBehavior(original, roundTripped, 0) {
			t.Errorf("%s: %s", filepath.Base(path), problem)
		}
	}
}

// TestRuntimeVocabulary compares what seccat accepts with what runc reports
// supporting (runc features, runc 1.5.1).
func TestRuntimeVocabulary(t *testing.T) {
	data, err := os.ReadFile("testdata/runc-features.json")
	if err != nil {
		t.Fatal(err)
	}
	var features struct {
		Linux struct {
			Seccomp struct {
				Enabled   bool
				Actions   []string
				Operators []string
				Archs     []string
			}
		}
	}
	if err := json.Unmarshal(data, &features); err != nil {
		t.Fatal(err)
	}
	sc := features.Linux.Seccomp
	if !sc.Enabled || len(sc.Actions) == 0 {
		t.Fatalf("runc-features.json has no seccomp section: %+v", sc)
	}
	same := func(what string, ours, theirs []string) {
		t.Helper()
		if !slices.Equal(sortedCopy(ours), sortedCopy(theirs)) {
			t.Errorf("%s: seccat accepts %v, runc supports %v", what, sortedCopy(ours), sortedCopy(theirs))
		}
	}
	same("actions", validActions, sc.Actions)
	same("operators", validOps, sc.Operators)

	// Every architecture runc supports is known to seccat, and every one that
	// --arch accepts is one runc supports.
	var runcArchs []string
	for _, a := range sc.Archs {
		runcArchs = append(runcArchs, archFromJSON(a))
	}
	for _, a := range runcArchs {
		if !slices.Contains(knownSeccompArches, a) {
			t.Errorf("runc supports %s, which seccat does not know", a)
		}
	}
	for _, a := range arches {
		if !slices.Contains(runcArchs, a.seccomp) {
			t.Errorf("--arch %s maps to %s, which runc does not support", a.native, a.seccomp)
		}
	}
}

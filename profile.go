// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Profile mirrors the Docker/Podman seccomp profile JSON (moby's
// profiles/seccomp types plus the OCI fields they inherit).
type Profile struct {
	DefaultAction    string      `json:"defaultAction"`
	DefaultErrnoRet  *uint       `json:"defaultErrnoRet,omitempty"`
	DefaultErrno     string      `json:"defaultErrno,omitempty"` // Podman, read-only
	Architectures    []string    `json:"architectures,omitempty"`
	ArchMap          []ArchEntry `json:"archMap,omitempty"`
	Flags            []string    `json:"flags,omitempty"`
	ListenerPath     string      `json:"listenerPath,omitempty"`
	ListenerMetadata string      `json:"listenerMetadata,omitempty"`
	Syscalls         []Entry     `json:"syscalls"`
}

// ArchEntry is one archMap element: a native architecture and its sub-architectures.
type ArchEntry struct {
	Architecture    string   `json:"architecture"`
	SubArchitecture []string `json:"subArchitectures,omitempty"`
}

// Entry is one syscalls[] element. Absent and zero differ for ErrnoRet, so it is a pointer.
type Entry struct {
	Name     string   `json:"name,omitempty"` // deprecated; use Names
	Names    []string `json:"names,omitempty"`
	Action   string   `json:"action"`
	ErrnoRet *uint    `json:"errnoRet,omitempty"`
	Errno    string   `json:"errno,omitempty"` // Podman, read-only
	Args     []Arg    `json:"args,omitempty"`
	Comment  string   `json:"comment,omitempty"`
	Includes *Filter  `json:"includes,omitempty"`
	Excludes *Filter  `json:"excludes,omitempty"`
}

// Filter holds the includes/excludes conditions of an entry.
type Filter struct {
	Caps      []string `json:"caps,omitempty"`
	Arches    []string `json:"arches,omitempty"`
	MinKernel *string  `json:"minKernel,omitempty"`
}

// Arg is a syscall argument comparison.
type Arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}

var validActions = []string{
	"SCMP_ACT_ALLOW",
	"SCMP_ACT_ERRNO",
	"SCMP_ACT_KILL",
	"SCMP_ACT_KILL_PROCESS",
	"SCMP_ACT_KILL_THREAD",
	"SCMP_ACT_LOG",
	"SCMP_ACT_NOTIFY",
	"SCMP_ACT_TRACE",
	"SCMP_ACT_TRAP",
}

var validOps = []string{
	"SCMP_CMP_EQ",
	"SCMP_CMP_GE",
	"SCMP_CMP_GT",
	"SCMP_CMP_LE",
	"SCMP_CMP_LT",
	"SCMP_CMP_MASKED_EQ",
	"SCMP_CMP_NE",
}

// LoadProfile decodes and validates a profile. The input is a Docker or Podman
// profile, an OCI linux.seccomp object, or an OCI bundle's config.json, from
// which linux.seccomp is taken. The returned warnings list JSON paths of fields
// this tool does not know about.
func LoadProfile(r io.Reader) (*Profile, []string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	data, prefix, err := seccompSection(data)
	if err != nil {
		return nil, nil, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, nil, fmt.Errorf("decoding profile: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, nil, err
	}
	warnings, err := unknownFields(data)
	if err != nil {
		return nil, nil, err
	}
	for i := range warnings {
		warnings[i] = prefix + warnings[i]
	}
	return &p, warnings, nil
}

// seccompSection returns the seccomp object of an OCI config.json, recognized
// by its ociVersion key, with the path prefix for warnings. Any other input is
// returned unchanged, including input that is not a JSON object, so that the
// regular decoding reports the error.
func seccompSection(data []byte) ([]byte, string, error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return data, "", nil
	}
	if _, ok := top["ociVersion"]; !ok {
		return data, "", nil
	}
	var linux map[string]json.RawMessage
	if raw := top["linux"]; len(raw) > 0 && json.Unmarshal(raw, &linux) != nil {
		return nil, "", errors.New("config.json: linux is not an object")
	}
	raw := linux["seccomp"]
	if len(raw) == 0 || string(raw) == "null" {
		return nil, "", errors.New("config.json has no linux.seccomp section: the container has no seccomp profile")
	}
	return raw, "linux.seccomp.", nil
}

// Encode writes the profile as JSON indented with tabs and without a final
// newline, as Docker and Podman write theirs.
func (p *Profile) Encode(w io.Writer) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "\t")
	if err := enc.Encode(p); err != nil { // Encode adds the newline
		return err
	}
	_, err := w.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return err
}

func (p *Profile) validate() error {
	if !slices.Contains(validActions, p.DefaultAction) {
		return fmt.Errorf("defaultAction: unknown action %q", p.DefaultAction)
	}
	for i := range p.Syscalls {
		if err := p.Syscalls[i].validate(); err != nil {
			return fmt.Errorf("syscalls[%d]: %w", i, err)
		}
	}
	return nil
}

func (e *Entry) validate() error {
	if e.Name != "" && len(e.Names) != 0 {
		return errors.New("both 'name' and 'names' are specified, use either")
	}
	if e.Name == "" && len(e.Names) == 0 {
		return errors.New("no syscall names")
	}
	if !slices.Contains(validActions, e.Action) {
		return fmt.Errorf("unknown action %q", e.Action)
	}
	for i, a := range e.Args {
		if a.Index > 5 {
			return fmt.Errorf("args[%d]: index %d out of range 0-5", i, a.Index)
		}
		if !slices.Contains(validOps, a.Op) {
			return fmt.Errorf("args[%d]: unknown op %q", i, a.Op)
		}
	}
	for _, f := range []struct {
		name string
		f    *Filter
	}{{"includes", e.Includes}, {"excludes", e.Excludes}} {
		if f.f != nil && f.f.MinKernel != nil {
			if _, err := parseVersion(*f.f.MinKernel); err != nil {
				return fmt.Errorf("%s.minKernel: %w", f.name, err)
			}
		}
	}
	return nil
}

// AllNames returns the syscall names of the entry, folding the deprecated
// single name into the list.
func (e *Entry) AllNames() []string {
	if e.Name != "" {
		return []string{e.Name}
	}
	return e.Names
}

// Version is a kernel version as {major, minor, patch}.
type Version [3]int

// releaseRe matches the leading X.Y[.Z] of a kernel release.
var releaseRe = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?`)

// parseRelease reads a kernel release as uname -r prints it, such as
// 7.2.8-200.fc44.x86_64, 7.0.0-1020-raspi, 3.12-1-amd64 or 5.10.103+. Only the
// leading X.Y[.Z] counts and the rest is ignored, as Docker does when it reads the
// host's kernel. A profile's minKernel is stricter and goes through parseVersion.
func parseRelease(s string) (Version, error) {
	m := releaseRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("invalid kernel release %q, want X.Y[.Z] with an optional suffix, as uname -r prints", s)
	}
	var v Version
	for i, part := range m[1:] {
		if part != "" {
			v[i], _ = strconv.Atoi(part) // digits only, by the pattern; an overflow cannot happen for kernel releases
		}
	}
	return v, nil
}

func parseVersion(s string) (Version, error) {
	var v Version
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return v, fmt.Errorf("invalid kernel version %q, want X.Y[.Z]", s)
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return v, fmt.Errorf("invalid kernel version %q, want X.Y[.Z]", s)
		}
		v[i] = n
	}
	return v, nil
}

var (
	knownTop = []string{
		"archMap",
		"architectures",
		"defaultAction",
		"defaultErrno",
		"defaultErrnoRet",
		"flags",
		"listenerMetadata",
		"listenerPath",
		"syscalls",
	}
	knownArchMap = []string{
		"architecture",
		"subArchitectures",
	}
	knownEntry = []string{
		"action",
		"args",
		"comment",
		"errno",
		"errnoRet",
		"excludes",
		"includes",
		"name",
		"names",
	}
	knownFilter = []string{
		"arches",
		"caps",
		"minKernel",
	}
	knownArg = []string{
		"index",
		"op",
		"value",
		"valueTwo",
	}
)

// unknownFields returns the JSON paths of keys not part of the profile schema.
func unknownFields(data []byte) ([]string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("decoding profile: %w", err)
	}
	var out []string
	check := func(path string, m map[string]json.RawMessage, known []string) {
		for k := range m {
			if !slices.Contains(known, k) {
				out = append(out, path+k)
			}
		}
	}
	// Elements were already decoded successfully into typed structs, so
	// errors from the loosely typed re-decodes below cannot occur.
	list := func(raw json.RawMessage) []map[string]json.RawMessage {
		var l []map[string]json.RawMessage
		_ = json.Unmarshal(raw, &l)
		return l
	}
	obj := func(raw json.RawMessage) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(raw, &m)
		return m
	}
	check("", top, knownTop)
	for i, m := range list(top["archMap"]) {
		check(fmt.Sprintf("archMap[%d].", i), m, knownArchMap)
	}
	for i, e := range list(top["syscalls"]) {
		path := fmt.Sprintf("syscalls[%d].", i)
		check(path, e, knownEntry)
		for _, k := range []string{"includes", "excludes"} {
			if raw, ok := e[k]; ok {
				check(path+k+".", obj(raw), knownFilter)
			}
		}
		for j, a := range list(e["args"]) {
			check(fmt.Sprintf("%sargs[%d].", path, j), a, knownArg)
		}
	}
	slices.Sort(out)
	return out, nil
}

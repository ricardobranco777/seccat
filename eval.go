// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"slices"
	"strings"
)

// Context says what is known about the container. Each field removes one kind
// of condition; anything left unknown stays in the output as a condition.
type Context struct {
	Caps   map[string]bool // nil: unknown. Non-nil, even if empty: the exact bounding set.
	Arch   string          // native name (see arch.go), "" if unknown
	Kernel *Version

	// Syscalls, if set (--all), are all syscalls of Arch; those left without a rule get the default action.
	Syscalls []string
}

// Eval partially evaluates the doc, the way dockerd and Podman filter a
// profile before handing it to the OCI runtime. For each condition: known true
// means it is removed, known false drops the rule, unknown keeps it. It does
// not model what libseccomp does when several kept rules overlap.
//
// Moby: daemon/pkg/seccomp (profiles/seccomp/seccomp_linux.go, setupSeccomp).
// Podman: containers/common pkg/seccomp/seccomp_linux.go, same semantics.
func (d *Doc) Eval(c Context) (*Doc, []string) {
	out := *d
	out.Rules = nil
	for _, r := range d.Rules {
		if conds, ok := r.Conds.eval(c); ok {
			r.Conds = conds
			out.Rules = append(out.Rules, r)
		}
	}
	var warnings []string
	if c.Arch != "" && len(d.Arch) > 0 {
		out.Arch = nil
		want := seccompName(c.Arch)
		for _, a := range d.Arch {
			if a.Arch == want {
				out.Arch = append(out.Arch, a)
			}
		}
		if len(out.Arch) == 0 && len(d.Architectures) == 0 {
			warnings = append(warnings, fmt.Sprintf("no @arch entry for %s", want))
		}
	}
	return &out, warnings
}

// eval reports the remaining conditions, or false if the rule can never apply.
func (c Conds) eval(ctx Context) (Conds, bool) {
	if ctx.Caps != nil {
		for _, s := range c.Caps {
			if !ctx.Caps[s] {
				return c, false
			}
		}
		for _, s := range c.NotCaps {
			if ctx.Caps[s] {
				return c, false
			}
		}
		c.Caps, c.NotCaps = nil, nil
	}
	if ctx.Arch != "" {
		if len(c.Arches) > 0 && !slices.Contains(c.Arches, ctx.Arch) {
			return c, false
		}
		if slices.Contains(c.NotArches, ctx.Arch) {
			return c, false
		}
		c.Arches, c.NotArches = nil, nil
	}
	if ctx.Kernel != nil {
		// Validated at load/parse time, so the errors cannot happen.
		if c.KernelGE != "" {
			if v, _ := parseVersion(c.KernelGE); slices.Compare(ctx.Kernel[:], v[:]) < 0 {
				return c, false
			}
			c.KernelGE = ""
		}
		if c.KernelLT != "" {
			if v, _ := parseVersion(c.KernelLT); slices.Compare(ctx.Kernel[:], v[:]) >= 0 {
				return c, false
			}
			c.KernelLT = ""
		}
	}
	return c, true
}

// allCaps is every Linux capability (linux/capability.h, CAP_CHOWN..CAP_CHECKPOINT_RESTORE).
var allCaps = []string{
	"AUDIT_CONTROL",
	"AUDIT_READ",
	"AUDIT_WRITE",
	"BLOCK_SUSPEND",
	"BPF",
	"CHECKPOINT_RESTORE",
	"CHOWN",
	"DAC_OVERRIDE",
	"DAC_READ_SEARCH",
	"FOWNER",
	"FSETID",
	"IPC_LOCK",
	"IPC_OWNER",
	"KILL",
	"LEASE",
	"LINUX_IMMUTABLE",
	"MAC_ADMIN",
	"MAC_OVERRIDE",
	"MKNOD",
	"NET_ADMIN",
	"NET_BIND_SERVICE",
	"NET_BROADCAST",
	"NET_RAW",
	"PERFMON",
	"SETFCAP",
	"SETGID",
	"SETPCAP",
	"SETUID",
	"SYS_ADMIN",
	"SYS_BOOT",
	"SYS_CHROOT",
	"SYS_MODULE",
	"SYS_NICE",
	"SYS_PACCT",
	"SYS_PTRACE",
	"SYS_RAWIO",
	"SYS_RESOURCE",
	"SYS_TIME",
	"SYS_TTY_CONFIG",
	"SYSLOG",
	"WAKE_ALARM",
}

var capPresets = map[string][]string{
	"none": {},
	"all":  allCaps,
	// moby daemon/pkg/oci/caps/defaults.go, DefaultCapabilities
	"docker": {
		"AUDIT_WRITE",
		"CHOWN",
		"DAC_OVERRIDE",
		"FOWNER",
		"FSETID",
		"KILL",
		"MKNOD",
		"NET_BIND_SERVICE",
		"NET_RAW",
		"SETFCAP",
		"SETGID",
		"SETPCAP",
		"SETUID",
		"SYS_CHROOT",
	},
	// containers/common pkg/config/default.go, DefaultCapabilities
	"podman": {
		"CHOWN",
		"DAC_OVERRIDE",
		"FOWNER",
		"FSETID",
		"KILL",
		"NET_BIND_SERVICE",
		"SETFCAP",
		"SETGID",
		"SETPCAP",
		"SETUID",
		"SYS_CHROOT",
	},
}

// parseCaps reads a --caps value: a comma-separated list whose items are
// capability names, with or without CAP_, or preset names that stand for their
// whole set. "docker,SYS_ADMIN" is Docker's defaults plus SYS_ADMIN, like
// docker run --cap-add SYS_ADMIN. An empty value is the empty set, which is what
// capsh --print shows for a container with every capability dropped. A non-nil
// result with no entries is a known, empty set ("none").
func parseCaps(s string) (map[string]bool, error) {
	set := map[string]bool{}
	if strings.TrimSpace(s) == "" {
		return set, nil
	}
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if names, ok := capPresets[strings.ToLower(item)]; ok {
			for _, n := range names {
				set[n] = true
			}
			continue
		}
		n := capFromJSON(item)
		if !slices.Contains(allCaps, n) {
			return nil, fmt.Errorf("unknown capability or preset %q", item)
		}
		set[n] = true
	}
	return set, nil
}

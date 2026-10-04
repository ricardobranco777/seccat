// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// WriteText writes the doc in the text format described in FORMAT.md.
func (d *Doc) WriteText(w io.Writer) error { return d.writeText(w, false) }

// WriteNumericText is WriteText with every argument value as a number.
func (d *Doc) WriteNumericText(w io.Writer) error { return d.writeText(w, true) }

func (d *Doc) writeText(w io.Writer, numeric bool) error {
	var bw strings.Builder
	fmt.Fprintf(&bw, "@default\t%s\n", d.Default)
	for _, a := range d.Arch {
		fmt.Fprintf(&bw, "@arch\t%s", a.Arch)
		if len(a.Subs) > 0 {
			fmt.Fprintf(&bw, "\t%s", strings.Join(a.Subs, ","))
		}
		bw.WriteByte('\n')
	}
	if len(d.Architectures) > 0 {
		fmt.Fprintf(&bw, "@architectures\t%s\n", strings.Join(d.Architectures, ","))
	}
	for _, f := range d.Flags {
		fmt.Fprintf(&bw, "@flag\t%s\n", f)
	}
	if d.ListenerPath != "" {
		fmt.Fprintf(&bw, "@listenerPath\t%s\n", escape(d.ListenerPath))
	}
	if d.ListenerMetadata != "" {
		fmt.Fprintf(&bw, "@listenerMetadata\t%s\n", escape(d.ListenerMetadata))
	}
	lines := make([]string, len(d.Rules))
	for i := range d.Rules {
		lines[i] = d.Rules[i].text(numeric)
	}
	slices.SortFunc(lines, naturalCompare)
	for _, l := range lines {
		bw.WriteString(l)
		bw.WriteByte('\n')
	}
	_, err := io.WriteString(w, bw.String())
	return err
}

// String renders the rule as one text-format line (without newline).
func (r *Rule) String() string { return r.text(false) }

func (r *Rule) text(numeric bool) string {
	fields := []string{r.Name, r.Action.String()}
	if c := r.condString(numeric); c != "" {
		fields = append(fields, c)
	}
	if r.Comment != "" {
		fields = append(fields, "# "+escape(r.Comment))
	}
	return strings.Join(fields, "\t")
}

func (r *Rule) condString(numeric bool) string {
	c := &r.Conds
	var parts []string
	for _, a := range c.Args {
		parts = append(parts, r.argString(a, numeric))
	}
	for _, s := range c.Caps {
		parts = append(parts, "cap:"+s)
	}
	for _, s := range c.NotCaps {
		parts = append(parts, "!cap:"+s)
	}
	if len(c.Arches) > 0 {
		parts = append(parts, "arch:"+strings.Join(c.Arches, ","))
	}
	if len(c.NotArches) > 0 {
		parts = append(parts, "!arch:"+strings.Join(c.NotArches, ","))
	}
	if c.KernelGE != "" {
		parts = append(parts, "kernel>="+c.KernelGE)
	}
	if c.KernelLT != "" {
		parts = append(parts, "kernel<"+c.KernelLT)
	}
	return strings.Join(parts, " && ")
}

// table returns the symbol table used to render argument idx of this rule, if
// any. NETLINK_* names only make sense when the same rule selects AF_NETLINK.
func (r *Rule) table(idx uint) *symTable {
	t := argTables[argKey{r.Name, idx}]
	if t == netlinkTable && !slices.ContainsFunc(r.Conds.Args, func(a ArgCond) bool {
		return a.Index == 0 && a.Op == "==" && a.Value == unix.AF_NETLINK
	}) {
		return nil
	}
	return t
}

func (r *Rule) argString(a ArgCond, numeric bool) string {
	var t *symTable
	if !numeric {
		t = r.table(a.Index)
	}
	switch a.Op {
	case "&":
		return fmt.Sprintf("arg%d&%s==%s", a.Index, maskString(t, a.Value), valueString(t, a.ValueTwo))
	case "==", "!=":
		return fmt.Sprintf("arg%d%s%s", a.Index, a.Op, valueString(t, a.Value))
	}
	// Names mean nothing for ordering comparisons (arg0<3 is not "less than AF_INET").
	return fmt.Sprintf("arg%d%s%d", a.Index, a.Op, a.Value)
}

// valueString renders a compared value: names where fully known, else decimal
// (hex for flag sets, where the bit pattern is what matters).
func valueString(t *symTable, v uint64) string {
	if t != nil {
		if s, ok := t.names(v); ok {
			return s
		}
		if t.flags && v != 0 {
			return fmt.Sprintf("0x%x", v)
		}
	}
	return strconv.FormatUint(v, 10)
}

// maskString renders a mask: names if every bit has one, else hex.
func maskString(t *symTable, v uint64) string {
	if t != nil {
		if s, ok := t.names(v); ok {
			if strings.Contains(s, "|") {
				return "(" + s + ")"
			}
			return s
		}
	}
	return fmt.Sprintf("0x%x", v)
}

var escaper = strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\n", `\n`)

// escape protects free text (comments, listener settings) from the field and line separators.
func escape(s string) string { return escaper.Replace(s) }

// naturalCompare orders strings with digit runs compared by numeric value, so
// that "arg0==8" sorts before "arg0==10". Ties on value fall back to the raw
// run, which keeps the order total and deterministic.
func naturalCompare(a, b string) int {
	for a != "" && b != "" {
		if isDigit(a[0]) && isDigit(b[0]) {
			na, nb := digitRun(a), digitRun(b)
			if c := compareNumeric(a[:na], b[:nb]); c != 0 {
				return c
			}
			a, b = a[na:], b[nb:]
			continue
		}
		if a[0] != b[0] {
			return int(a[0]) - int(b[0])
		}
		a, b = a[1:], b[1:]
	}
	return len(a) - len(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func digitRun(s string) int {
	n := 0
	for n < len(s) && isDigit(s[n]) {
		n++
	}
	return n
}

// compareNumeric compares digit strings by value without overflow, then by raw text.
func compareNumeric(a, b string) int {
	ta, tb := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(ta) != len(tb) {
		return len(ta) - len(tb)
	}
	if c := strings.Compare(ta, tb); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

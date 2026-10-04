// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ParseText reads the text format. Errors carry the offending line number.
func ParseText(r io.Reader) (*Doc, error) {
	d := &Doc{}
	sawDefault := false
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var err error
		if strings.HasPrefix(line, "@") {
			err = d.parseHeader(line, &sawDefault)
		} else {
			err = d.parseRule(line)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !sawDefault {
		return nil, errors.New("missing @default line")
	}
	return d, nil
}

func (d *Doc) parseHeader(line string, sawDefault *bool) error {
	f := strings.Split(line, "\t")
	want := func(lo, hi int) error {
		if len(f)-1 < lo || len(f)-1 > hi {
			return fmt.Errorf("%s: wrong number of fields", f[0])
		}
		return nil
	}
	switch f[0] {
	case "@default":
		if err := want(1, 1); err != nil {
			return err
		}
		if *sawDefault {
			return errors.New("duplicate @default")
		}
		a, err := parseAction(f[1])
		if err != nil {
			return err
		}
		d.Default, *sawDefault = a, true
	case "@arch":
		if err := want(1, 2); err != nil {
			return err
		}
		a := ArchLine{Arch: f[1]}
		if len(f) == 3 {
			a.Subs = strings.Split(f[2], ",")
		}
		d.Arch = append(d.Arch, a)
	case "@architectures":
		if err := want(1, 1); err != nil {
			return err
		}
		d.Architectures = strings.Split(f[1], ",")
	case "@flag":
		if err := want(1, 1); err != nil {
			return err
		}
		d.Flags = append(d.Flags, f[1])
	case "@listenerPath", "@listenerMetadata":
		if err := want(1, 1); err != nil {
			return err
		}
		s, err := unescape(f[1])
		if err != nil {
			return err
		}
		if f[0] == "@listenerPath" {
			d.ListenerPath = s
		} else {
			d.ListenerMetadata = s
		}
	default:
		return fmt.Errorf("unknown header %s", f[0])
	}
	return nil
}

func (d *Doc) parseRule(line string) error {
	f := strings.Split(line, "\t")
	if len(f) < 2 || f[0] == "" {
		return errors.New("want NAME<TAB>ACTION[<TAB>CONDITIONS][<TAB># COMMENT]")
	}
	r := Rule{Name: f[0]}
	var err error
	if r.Action, err = parseAction(f[1]); err != nil {
		return err
	}
	rest := f[2:]
	if n := len(rest); n > 0 && (rest[n-1] == "#" || strings.HasPrefix(rest[n-1], "# ")) {
		if r.Comment, err = unescape(strings.TrimPrefix(strings.TrimPrefix(rest[n-1], "#"), " ")); err != nil {
			return err
		}
		rest = rest[:n-1]
	}
	switch len(rest) {
	case 0:
	case 1:
		if r.Conds, err = parseConds(r.Name, rest[0]); err != nil {
			return err
		}
	default:
		return errors.New("too many fields")
	}
	d.Rules = append(d.Rules, r)
	return nil
}

func parseAction(s string) (Action, error) {
	name, arg, hasArg := strings.Cut(s, "(")
	if !slices.Contains(validActions, actPrefix+name) {
		return Action{}, fmt.Errorf("unknown action %q", name)
	}
	a := Action{Name: name}
	if hasArg {
		inner, ok := strings.CutSuffix(arg, ")")
		if !ok {
			return Action{}, fmt.Errorf("malformed action %q", s)
		}
		n, err := parseActionRet(inner)
		if err != nil {
			return Action{}, err
		}
		a.Ret = &n
	}
	return a, nil
}

var (
	argRe  = regexp.MustCompile(`^arg([0-9]+)(==|!=|<=|>=|<|>|&)(.+)$`)
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

func parseConds(syscall, s string) (Conds, error) {
	var c Conds
	for term := range strings.SplitSeq(s, " && ") {
		if err := c.parseTerm(syscall, term); err != nil {
			return Conds{}, fmt.Errorf("condition %q: %w", term, err)
		}
	}
	slices.SortStableFunc(c.Args, func(a, b ArgCond) int { return int(a.Index) - int(b.Index) })
	slices.Sort(c.Caps)
	slices.Sort(c.NotCaps)
	slices.Sort(c.Arches)
	slices.Sort(c.NotArches)
	return c, nil
}

func (c *Conds) parseTerm(syscall, term string) error {
	setOnce := func(dst *[]string, list string) error {
		if *dst != nil {
			return errors.New("duplicate condition")
		}
		*dst = strings.Split(list, ",")
		return nil
	}
	setVersion := func(dst *string, v string) error {
		if *dst != "" {
			return errors.New("duplicate condition")
		}
		if _, err := parseVersion(v); err != nil {
			return err
		}
		*dst = v
		return nil
	}
	addCap := func(dst *[]string, name string) error {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("bad capability %q", name)
		}
		*dst = append(*dst, capFromJSON(name))
		return nil
	}
	switch {
	case strings.HasPrefix(term, "!cap:"):
		return addCap(&c.NotCaps, term[5:])
	case strings.HasPrefix(term, "cap:"):
		return addCap(&c.Caps, term[4:])
	case strings.HasPrefix(term, "!arch:"):
		return setOnce(&c.NotArches, term[6:])
	case strings.HasPrefix(term, "arch:"):
		return setOnce(&c.Arches, term[5:])
	case strings.HasPrefix(term, "kernel>="):
		return setVersion(&c.KernelGE, term[8:])
	case strings.HasPrefix(term, "kernel<"):
		return setVersion(&c.KernelLT, term[7:])
	case strings.HasPrefix(term, "arg"):
		a, err := parseArg(syscall, term)
		if err != nil {
			return err
		}
		c.Args = append(c.Args, a)
		return nil
	}
	return errors.New("unknown condition")
}

func parseArg(syscall, term string) (ArgCond, error) {
	m := argRe.FindStringSubmatch(term)
	if m == nil {
		return ArgCond{}, errors.New("malformed argument condition")
	}
	idx, _ := strconv.Atoi(m[1])
	if idx > 5 {
		return ArgCond{}, fmt.Errorf("argument index %d out of range 0-5", idx)
	}
	a := ArgCond{Index: uint(idx), Op: m[2]}
	var err error
	if a.Op == "&" {
		mask, val, ok := strings.Cut(m[3], "==")
		if !ok {
			return a, errors.New("masked comparison needs ==")
		}
		t := argTables[argKey{syscall, a.Index}]
		if a.Value, err = parseValueExpr(t, mask); err != nil {
			return a, err
		}
		a.ValueTwo, err = parseValueExpr(t, val)
		return a, err
	}
	a.Value, err = parseValueExpr(argTables[argKey{syscall, a.Index}], m[3])
	return a, err
}

// parseNumber accepts decimal and 0x-prefixed hex. A leading 0 is not octal.
func parseNumber(s string) (uint64, error) {
	base := 10
	if h, ok := strings.CutPrefix(s, "0x"); ok {
		s, base = h, 16
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, fmt.Errorf("bad number %q", s)
	}
	return n, nil
}

func unescape(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			sb.WriteByte(s[i])
			continue
		}
		i++
		if i == len(s) {
			return "", errors.New("trailing backslash")
		}
		switch s[i] {
		case '\\':
			sb.WriteByte('\\')
		case 't':
			sb.WriteByte('\t')
		case 'n':
			sb.WriteByte('\n')
		default:
			return "", fmt.Errorf(`unknown escape \%c`, s[i])
		}
	}
	return sb.String(), nil
}

// Profile converts the doc back to profile JSON. Rules with equal action,
// conditions and comment share an entry; a name repeated under the same key
// gets a further entry rather than being merged.
func (d *Doc) Profile() *Profile {
	p := &Profile{
		DefaultAction:    actPrefix + d.Default.Name,
		DefaultErrnoRet:  d.Default.Ret,
		Architectures:    archesToJSON(d.Architectures),
		Flags:            d.Flags,
		ListenerPath:     d.ListenerPath,
		ListenerMetadata: d.ListenerMetadata,
		Syscalls:         []Entry{},
	}
	for _, a := range d.Arch {
		p.ArchMap = append(p.ArchMap, ArchEntry{archToJSON(a.Arch), archesToJSON(a.Subs)})
	}

	type group struct {
		rule   Rule
		layers [][]string // layers[i] holds the i-th occurrence of each name
		seen   map[string]int
	}
	groups := map[string]*group{}
	var order []*group
	for _, r := range d.Rules {
		k := r.key()
		g := groups[k]
		if g == nil {
			g = &group{rule: r, seen: map[string]int{}}
			groups[k] = g
			order = append(order, g)
		}
		layer := g.seen[r.Name]
		g.seen[r.Name]++
		if layer == len(g.layers) {
			g.layers = append(g.layers, nil)
		}
		g.layers[layer] = append(g.layers[layer], r.Name)
	}
	for _, g := range order {
		for _, names := range g.layers {
			e := g.rule.entry()
			e.Names = sortedCopy(names)
			p.Syscalls = append(p.Syscalls, e)
		}
	}
	slices.SortStableFunc(p.Syscalls, func(a, b Entry) int {
		return strings.Compare(a.Names[0], b.Names[0])
	})
	return p
}

// key identifies everything but the name.
func (r *Rule) key() string {
	c := *r
	c.Name = ""
	return c.String()
}

func archToJSON(s string) string { return archPrefix + strings.ToUpper(s) }

func archesToJSON(l []string) []string {
	var out []string
	for _, s := range l {
		out = append(out, archToJSON(s))
	}
	return out
}

var jsonOps = func() map[string]string {
	m := map[string]string{}
	for k, v := range opSymbols {
		m[v] = k
	}
	return m
}()

// entry builds the JSON entry for the rule, minus names.
func (r *Rule) entry() Entry {
	e := Entry{
		Action:   actPrefix + r.Action.Name,
		ErrnoRet: r.Action.Ret,
		Comment:  r.Comment,
	}
	for _, a := range r.Conds.Args {
		e.Args = append(e.Args, Arg{Index: a.Index, Value: a.Value, ValueTwo: a.ValueTwo, Op: jsonOps[a.Op]})
	}
	c := &r.Conds
	e.Includes = newFilter(c.Caps, c.Arches, c.KernelGE)
	e.Excludes = newFilter(c.NotCaps, c.NotArches, c.KernelLT)
	return e
}

func newFilter(caps, arches []string, kernel string) *Filter {
	if len(caps) == 0 && len(arches) == 0 && kernel == "" {
		return nil
	}
	f := &Filter{Arches: arches}
	for _, c := range caps {
		f.Caps = append(f.Caps, capPrefix+c)
	}
	if kernel != "" {
		f.MinKernel = &kernel
	}
	return f
}

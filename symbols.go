// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// errnoPreferred renames what ErrnoName reports where the kernel uses another
// name for the number (95 is EOPNOTSUPP in the kernel, ENOTSUP in x/sys).
var errnoPreferred = map[string]string{
	"EFSCORRUPTED": "EUCLEAN",
	"ENOTSUP":      "EOPNOTSUPP",
}

func errnoName(n uint) string {
	name := unix.ErrnoName(syscall.Errno(n))
	if p, ok := errnoPreferred[name]; ok {
		return p
	}
	return name
}

// errnoAliases are other names for numbers that errnoName reports under one
// name. They are accepted on input only, and are given by canonical name
// because some constants (EDEADLOCK) do not exist on every architecture.
var errnoAliases = map[string]string{
	"EDEADLOCK":    "EDEADLK",
	"EFSBADCRC":    "EBADMSG",
	"EFSCORRUPTED": "EUCLEAN",
	"ENOTSUP":      "EOPNOTSUPP",
	"EWOULDBLOCK":  "EAGAIN",
}

var errnoByName = func() map[string]uint {
	m := make(map[string]uint)
	for n := 1; n < 4096; n++ {
		if name := errnoName(uint(n)); name != "" {
			m[name] = uint(n)
		}
	}
	for alias, name := range errnoAliases {
		if n, ok := m[name]; ok {
			m[alias] = n
		}
	}
	return m
}()

// String renders the action as ALLOW, ERRNO, ERRNO(EPERM), TRACE(5), ...
// A bare name means the JSON had no errnoRet.
func (a Action) String() string {
	if a.Ret == nil {
		return a.Name
	}
	if a.Name == "ERRNO" {
		if n := errnoName(*a.Ret); n != "" {
			return a.Name + "(" + n + ")"
		}
	}
	return a.Name + "(" + strconv.FormatUint(uint64(*a.Ret), 10) + ")"
}

// parseActionRet resolves the text inside ERRNO(...) to a number: an errno
// name or a decimal.
func parseActionRet(s string) (uint, error) {
	if n, ok := errnoByName[s]; ok {
		return n, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unknown errno %q", s)
	}
	return uint(n), nil
}

// sym is one symbolic name for an argument value.
type sym struct {
	name  string
	value uint64
}

// symTable maps argument values to names. Enum tables hold one value per name;
// flag tables are decomposed into |-joined names. Aliases are accepted on
// input only, so output has one canonical name per value.
type symTable struct {
	flags  bool
	syms   []sym
	byName map[string]uint64
}

func newTable(flags bool, syms, aliases []sym) *symTable {
	t := &symTable{flags: flags, syms: syms, byName: map[string]uint64{}}
	if flags {
		slices.SortStableFunc(t.syms, func(a, b sym) int { return cmp.Compare(a.value, b.value) })
	}
	for _, s := range slices.Concat(syms, aliases) {
		t.byName[s.name] = s.value
	}
	return t
}

// names renders v as names, or reports false if some part of v has no name.
func (t *symTable) names(v uint64) (string, bool) {
	if !t.flags {
		for _, s := range t.syms {
			if s.value == v {
				return s.name, true
			}
		}
		return "", false
	}
	var parts []string
	rest := v
	for _, s := range t.syms {
		if s.value == 0 {
			if v == 0 {
				return s.name, true
			}
			continue
		}
		if rest&s.value == s.value {
			parts = append(parts, s.name)
			rest &^= s.value
		}
	}
	if rest != 0 || len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "|"), true
}

// The names come from x/sys/unix so no numbers are retyped here. PER_* is not
// in x/sys; the values are from linux/personality.h.
var (
	afTable = newTable(false, []sym{
		{"AF_ALG", unix.AF_ALG},
		{"AF_APPLETALK", unix.AF_APPLETALK},
		{"AF_ASH", unix.AF_ASH},
		{"AF_ATMPVC", unix.AF_ATMPVC},
		{"AF_ATMSVC", unix.AF_ATMSVC},
		{"AF_AX25", unix.AF_AX25},
		{"AF_BLUETOOTH", unix.AF_BLUETOOTH},
		{"AF_BRIDGE", unix.AF_BRIDGE},
		{"AF_CAIF", unix.AF_CAIF},
		{"AF_CAN", unix.AF_CAN},
		{"AF_ECONET", unix.AF_ECONET},
		{"AF_IB", unix.AF_IB},
		{"AF_IEEE802154", unix.AF_IEEE802154},
		{"AF_INET", unix.AF_INET},
		{"AF_INET6", unix.AF_INET6},
		{"AF_IPX", unix.AF_IPX},
		{"AF_IRDA", unix.AF_IRDA},
		{"AF_ISDN", unix.AF_ISDN},
		{"AF_IUCV", unix.AF_IUCV},
		{"AF_KCM", unix.AF_KCM},
		{"AF_KEY", unix.AF_KEY},
		{"AF_LLC", unix.AF_LLC},
		{"AF_MCTP", unix.AF_MCTP},
		{"AF_MPLS", unix.AF_MPLS},
		{"AF_NETBEUI", unix.AF_NETBEUI},
		{"AF_NETLINK", unix.AF_NETLINK},
		{"AF_NETROM", unix.AF_NETROM},
		{"AF_NFC", unix.AF_NFC},
		{"AF_PACKET", unix.AF_PACKET},
		{"AF_PHONET", unix.AF_PHONET},
		{"AF_PPPOX", unix.AF_PPPOX},
		{"AF_QIPCRTR", unix.AF_QIPCRTR},
		{"AF_RDS", unix.AF_RDS},
		{"AF_ROSE", unix.AF_ROSE},
		{"AF_RXRPC", unix.AF_RXRPC},
		{"AF_SECURITY", unix.AF_SECURITY},
		{"AF_SMC", unix.AF_SMC},
		{"AF_SNA", unix.AF_SNA},
		{"AF_TIPC", unix.AF_TIPC},
		{"AF_UNIX", unix.AF_UNIX},
		{"AF_UNSPEC", unix.AF_UNSPEC},
		{"AF_VSOCK", unix.AF_VSOCK},
		{"AF_WANPIPE", unix.AF_WANPIPE},
		{"AF_X25", unix.AF_X25},
		{"AF_XDP", unix.AF_XDP},
	}, []sym{
		{"AF_FILE", unix.AF_FILE},
		{"AF_LOCAL", unix.AF_LOCAL},
		{"AF_ROUTE", unix.AF_ROUTE},
	})

	// Only the protocol numbers: x/sys's NETLINK_* also holds setsockopt names.
	netlinkTable = newTable(false, []sym{
		{"NETLINK_AUDIT", unix.NETLINK_AUDIT},
		{"NETLINK_CONNECTOR", unix.NETLINK_CONNECTOR},
		{"NETLINK_CRYPTO", unix.NETLINK_CRYPTO},
		{"NETLINK_DNRTMSG", unix.NETLINK_DNRTMSG},
		{"NETLINK_ECRYPTFS", unix.NETLINK_ECRYPTFS},
		{"NETLINK_FIB_LOOKUP", unix.NETLINK_FIB_LOOKUP},
		{"NETLINK_FIREWALL", unix.NETLINK_FIREWALL},
		{"NETLINK_GENERIC", unix.NETLINK_GENERIC},
		{"NETLINK_IP6_FW", unix.NETLINK_IP6_FW},
		{"NETLINK_ISCSI", unix.NETLINK_ISCSI},
		{"NETLINK_KOBJECT_UEVENT", unix.NETLINK_KOBJECT_UEVENT},
		{"NETLINK_NETFILTER", unix.NETLINK_NETFILTER},
		{"NETLINK_NFLOG", unix.NETLINK_NFLOG},
		{"NETLINK_RDMA", unix.NETLINK_RDMA},
		{"NETLINK_ROUTE", unix.NETLINK_ROUTE},
		{"NETLINK_SCSITRANSPORT", unix.NETLINK_SCSITRANSPORT},
		{"NETLINK_SELINUX", unix.NETLINK_SELINUX},
		{"NETLINK_SMC", unix.NETLINK_SMC},
		{"NETLINK_SOCK_DIAG", unix.NETLINK_SOCK_DIAG},
		{"NETLINK_USERSOCK", unix.NETLINK_USERSOCK},
		{"NETLINK_XFRM", unix.NETLINK_XFRM},
	}, []sym{
		{"NETLINK_INET_DIAG", unix.NETLINK_INET_DIAG},
		{"NETLINK_UNUSED", unix.NETLINK_UNUSED},
	})

	personaTable = newTable(true, []sym{
		{"PER_LINUX", 0},
		{"PER_LINUX32", 0x0008},
		{"UNAME26", 0x20000},
	}, nil)

	cloneTable = newTable(true, []sym{
		{"CLONE_CHILD_CLEARTID", unix.CLONE_CHILD_CLEARTID},
		{"CLONE_CHILD_SETTID", unix.CLONE_CHILD_SETTID},
		{"CLONE_CLEAR_SIGHAND", unix.CLONE_CLEAR_SIGHAND},
		{"CLONE_DETACHED", unix.CLONE_DETACHED},
		{"CLONE_FILES", unix.CLONE_FILES},
		{"CLONE_FS", unix.CLONE_FS},
		{"CLONE_INTO_CGROUP", unix.CLONE_INTO_CGROUP},
		{"CLONE_IO", unix.CLONE_IO},
		{"CLONE_NEWCGROUP", unix.CLONE_NEWCGROUP},
		{"CLONE_NEWIPC", unix.CLONE_NEWIPC},
		{"CLONE_NEWNET", unix.CLONE_NEWNET},
		{"CLONE_NEWNS", unix.CLONE_NEWNS},
		{"CLONE_NEWPID", unix.CLONE_NEWPID},
		{"CLONE_NEWTIME", unix.CLONE_NEWTIME},
		{"CLONE_NEWUSER", unix.CLONE_NEWUSER},
		{"CLONE_NEWUTS", unix.CLONE_NEWUTS},
		{"CLONE_PARENT", unix.CLONE_PARENT},
		{"CLONE_PARENT_SETTID", unix.CLONE_PARENT_SETTID},
		{"CLONE_PIDFD", unix.CLONE_PIDFD},
		{"CLONE_PTRACE", unix.CLONE_PTRACE},
		{"CLONE_SETTLS", unix.CLONE_SETTLS},
		{"CLONE_SIGHAND", unix.CLONE_SIGHAND},
		{"CLONE_SYSVSEM", unix.CLONE_SYSVSEM},
		{"CLONE_THREAD", unix.CLONE_THREAD},
		{"CLONE_UNTRACED", unix.CLONE_UNTRACED},
		{"CLONE_VFORK", unix.CLONE_VFORK},
		{"CLONE_VM", unix.CLONE_VM},
	}, nil)
)

type argKey struct {
	syscall string
	index   uint
}

// argTables says which arguments have symbolic values. clone's flags are arg1
// on s390, where the argument order differs.
var argTables = map[argKey]*symTable{
	{"socket", 0}:      afTable,
	{"socket", 2}:      netlinkTable,
	{"personality", 0}: personaTable,
	{"clone", 0}:       cloneTable,
	{"clone", 1}:       cloneTable,
}

// parseValueExpr reads a number, a name from t, or a |-combination of them.
// Parentheses only group and are ignored.
func parseValueExpr(t *symTable, s string) (uint64, error) {
	if strings.Count(s, "(") != strings.Count(s, ")") {
		return 0, fmt.Errorf("unbalanced parentheses in %q", s)
	}
	var v uint64
	for part := range strings.SplitSeq(strings.NewReplacer("(", "", ")", "").Replace(s), "|") {
		if n, ok := t.lookup(part); ok {
			v |= n
			continue
		}
		n, err := parseNumber(part)
		if err != nil {
			return 0, err
		}
		v |= n
	}
	return v, nil
}

func (t *symTable) lookup(name string) (uint64, bool) {
	if t == nil {
		return 0, false
	}
	n, ok := t.byName[name]
	return n, ok
}

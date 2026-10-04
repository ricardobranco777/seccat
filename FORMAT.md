# seccat text format

The line-oriented language seccat uses for seccomp profile JSON. Converting a
profile to it and back keeps its behavior (see [Converting back](#converting-back---json)).

One record per line, fields separated by a single TAB. Blank lines and lines
starting with `#` are ignored on input. The same input always gives the same output.

## Header lines

Emitted first, in this order. Only `@default` is required on input.

```
@default	ERRNO(EPERM)             defaultAction + defaultErrnoRet
@arch	x86_64	x86,x32              one per archMap entry; sub-architectures optional
@architectures	x86_64,x86          top-level "architectures"
@flag	SECCOMP_FILTER_FLAG_LOG     one per flag
@listenerPath	/path
@listenerMetadata	text
```

Architecture names have `SCMP_ARCH_` stripped and are lowercased.
`@listenerPath` and `@listenerMetadata` use the escapes below.

## Rule lines

```
NAME	ACTION[	CONDITIONS][	# COMMENT]
```

One line per syscall name per JSON entry. Several lines for the same name are
alternatives; the conditions within one line must all hold.

### Action

`SCMP_ACT_` is stripped: `ALLOW`, `ERRNO`, `ERRNO(EPERM)`, `KILL`,
`KILL_PROCESS`, `KILL_THREAD`, `TRAP`, `TRACE`, `TRACE(5)`, `LOG`, `NOTIFY`.

A bare `ERRNO` means the entry has no `errnoRet` and inherits the profile
default. `ERRNO(EPERM)` is explicit. Errno numbers without a name stay numeric:
`ERRNO(4000)`.

### Conditions

Joined with ` && `. Output uses this order: args (by index), `cap:`, `!cap:`,
`arch:`, `!arch:`, kernel. Input accepts any order.

| JSON | Text |
|---|---|
| `includes.caps: [A,B]` (all required) | `cap:A && cap:B` |
| `excludes.caps: [A,B]` (rule is dropped if any is present) | `!cap:A && !cap:B` |
| `includes.arches: [x,y]` (any of) | `arch:x,y` |
| `excludes.arches: [x,y]` | `!arch:x,y` |
| `includes.minKernel: "4.8"` | `kernel>=4.8` |
| `excludes.minKernel: "4.8"` | `kernel<4.8` |
| arg `SCMP_CMP_EQ NE LT LE GT GE` | `arg0==V` `!=` `<` `<=` `>` `>=` |
| arg `SCMP_CMP_MASKED_EQ` (value is the mask, valueTwo the result) | `arg0&MASK==V` |

Capability names are written without `CAP_`; input accepts either, in any case.
`arch:` and `!arch:` keep the names the profile uses (`amd64`, `x86`, `s390x`). They
differ from the libseccomp names in `@arch` lines (`x86_64`, ...).
Only one `arch:`, one `!arch:`, and one of each kernel condition may appear per line.

### Symbolic values

Output uses names where one is known; input accepts names, decimal, `0x` hex,
`|` combinations, and parentheses (which only group).

| Syscall | Argument | Names |
|---|---|---|
| `socket` | arg0 | `AF_*` |
| `socket` | arg2, only when the line also has `arg0==AF_NETLINK` | `NETLINK_*` protocols |
| `personality` | arg0 | `PER_LINUX`, `PER_LINUX32`, `UNAME26` |
| `clone` | arg0 and arg1 (s390 passes flags in arg1) | `CLONE_*` |

Names are used for `==`, `!=` and masks only: `arg0<3` is not "less than
AF_INET". A value with any bit that has no name is written as hex for flag sets
and decimal for plain enums; a mask with an unnamed bit is hex. Aliases
(`AF_LOCAL`, `AF_ROUTE`, `NETLINK_INET_DIAG`) are accepted on input and written
canonically.

Errno names work the same way: a number has one name in the output. These other
names are accepted on input, with the name that is written in parentheses:
`EWOULDBLOCK` (`EAGAIN`), `EDEADLOCK` (`EDEADLK`), `EFSBADCRC` (`EBADMSG`),
`ENOTSUP` (`EOPNOTSUPP`) and `EFSCORRUPTED` (`EUCLEAN`). The names follow the
architecture seccat was built for; x86 and ARM agree.

### Comments

A final field starting with `# ` is the entry's `comment`.

### Escapes

In comments and listener settings: `\\`, `\t`, `\n`.

### Ordering

Header lines keep their order. Rule lines are sorted as whole lines with digit
runs compared by value, so `arg0==8` comes before `arg0==10`.

## Converting back (`--json`)

Lines with the same action, conditions and comment become one entry with a
sorted `names` list; entries are ordered by first name. A line repeated in the
text becomes a repeated entry, never merged (Podman's profile has one
such duplicate).

Behavior is preserved; the file is not. Not preserved: entry order and grouping,
formatting, unknown fields, `null` vs absent, `valueTwo` on non-masked args, and
Podman's `errno` / `defaultErrno` strings.

Podman's `errno` and `defaultErrno` names are read as numbers (in Podman a name
wins over the older `errnoRet`), so `--json` writes only the numbers, `errnoRet`
and `defaultErrnoRet`, which Podman and Docker both read.

# FAQ

The examples assume `seccat` is on the path. Apart from the first, they run in a
directory that holds `docker.json` and `podman.json` (the upstream profiles are
in `testdata/`).

## How do I compare the default Docker and Podman profiles?

The [README](README.md) has the command: it fetches both profiles from their
repositories and runs `diff` on what `seccat` makes of them. `-c docker` and
`-c podman` are each engine's default capabilities, `-a` and `-k` are the
architecture and kernel to compare for, and `-A` is explained in the entry about
differences that aren't real, below. `diff` exits with status 1 when the
profiles differ.

To compare for the machine you are on, use `-a "$(uname -m)"` and
`-k "$(uname -r)"`. `--kernel` reads the leading `X.Y[.Z]` of a kernel release and
ignores the rest, as Docker does, so `7.0.0-1020-raspi` on Ubuntu is 7.0.0.

Without the options you get the profiles as written, conditions included, which
is a different question.

## What does a default Docker container get for `clone3` and `ptrace`?

```
$ seccat -c docker -a amd64 -k 6.8 docker.json | grep -w -e clone3 -e ptrace
clone3	ERRNO(ENOSYS)
ptrace	ALLOW
```

A syscall that doesn't appear, such as `bpf` or `unshare`, has no rule that
applies, so it gets the profile's default: `EPERM` for Docker.

## What does `docker run --cap-add SYS_ADMIN` change?

Presets and capability names mix, so Docker's defaults plus `SYS_ADMIN` is
`docker,SYS_ADMIN`:

```
$ diff <(seccat -a amd64 -k 6.8 -c docker docker.json) \
       <(seccat -a amd64 -k 6.8 -c docker,SYS_ADMIN docker.json) | grep '^[<>]' | head -6
> bpf	ALLOW
< clone	ALLOW	arg0&(CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET)==0
< clone3	ERRNO(ENOSYS)
> clone	ALLOW
> clone3	ALLOW
> fanotify_init	ALLOW
```

26 syscalls change. 24 are allowed that had no rule before, among them `mount`,
`unshare`, `setns`, `bpf` and `perf_event_open`, and `clone` loses its
restriction on the namespace flags.

## What does Podman allow that Docker doesn't?

```
comm -13 <(seccat -c docker -a amd64 -k 6.8 docker.json | grep -w ALLOW | cut -f1 | sort -u) \
         <(seccat -c podman -a amd64 -k 6.8 podman.json | grep -w ALLOW | cut -f1 | sort -u)
```

That lists 23 syscalls, among them `clone3` and the new mount calls (`fsopen`,
`fsmount`, ...). Use `comm -23` for the 14 that only Docker allows.

## Why does diffing the two profiles show differences that aren't real?

The profiles have different defaults (`EPERM` for Docker, `ENOSYS` for Podman),
and Podman denies many syscalls explicitly with `EPERM`. A plain `diff` reports
such a syscall, `acct` for one, as different even though both return `EPERM`.

`--all` (`-A`), as in the command above, lists every syscall of the architecture
on both sides, which removes that noise. The diff gets longer (130 lines become
173 on the current snapshots), because the defaults differ and that now shows for
each syscall neither profile mentions. `--all` output is for comparing, not a
profile: converting it back would write an explicit rule for every syscall of one
architecture.

## Can I edit a profile with ordinary tools?

```
seccat docker.json | grep -vw ptrace | seccat --json > custom.json
```

## Does converting back give the same file?

No, it gives a profile that behaves the same. What changes: the order of the
entries and how syscalls are grouped into them, the formatting, fields seccat
doesn't know, and redundant fields (empty lists, `valueTwo` where it has no
meaning, Podman's `errno` names, whose numbers are kept). [FORMAT.md](FORMAT.md)
has the details.

## How can I check that a round trip kept the behavior?

Normalize the original and the round trip with
[`contrib/normalize.jq`](contrib/normalize.jq) and compare them. Nothing is
printed if they match (needs `jq`):

```
norm() { jq -S -c -f contrib/normalize.jq "$@" | sort; }
diff <(norm docker.json) <(seccat docker.json | seccat -j | norm)
```

The filter turns each entry into one line per syscall name, drops empty fields
and sorts the sets, so entry order and grouping don't count. That also hides a change
in the order of one syscall's rules, which can change the filter (see the entry on
argument conditions); `go test` checks that order. It also works on any
two profiles: `diff <(norm a.json) <(norm b.json)`.

## How is seccat tested?

seccat's evaluation follows the filtering code in moby (Docker), and Podman
filters the same way. The tests compare it with an independent copy of that logic
on the Docker and Podman default profiles, for several capability sets,
architectures and kernel versions. They also check that converting a profile to
text and back keeps its behavior, and that the OCI input handles real files from
`runc spec`.

The Go tests compare profiles as data. `make test-tools` also compiles the Docker
and Podman profiles with libseccomp, loads them, and checks with `secprobe` that the
kernel does what seccat says, for several capability sets. It still doesn't run a
container or runc.

## What happens if I mistype a capability, architecture or syscall name?

You get a warning on stderr and the exit status stays 0:

```
seccat: warning: unknown capability SYS_ADMN (clone3)
```

It matters because a rule that needs a capability nobody has would never apply,
and nothing else would tell you. Syscall names are checked against libseccomp's table
(`third_party/libseccomp`). A valid name that is newer than that table gets the
same warning; `make update-syscalls` refreshes it. A syscall that exists only on
some architectures is fine, since names are checked against all of them.
Malformed input, such as an unknown action, errno, operator or symbol name, is an
error with a line number.

## Which values does `--arch` take?

The names profiles use in `arch:` conditions (`amd64`, `x86`, `arm64`, `s390x`,
`riscv64`, ...), Go architecture names (`386`, `loong64`, `mipsle`, ...),
libseccomp names (`x86_64`, `aarch64`, ...) and `uname -m` values (`i686`,
`armv7l`, ...), so `--arch "$(uname -m)"` works. Several names can mean one
architecture: `amd64` and `x86_64` are the same, and so are `x86`, `386` and
`i686` (32-bit x86, which is not `amd64`). Profiles write `x86`, not `386`.

`uname -m` can't tell endianness, so `mips` and `mips64` mean big-endian; use
`mipsel`, `mipsel64` or the Go names `mipsle`, `mips64le` for little-endian. Debian
architecture names such as `armhf` and `ppc64el` are not accepted.

## Does seccat use this machine's architecture, kernel or capabilities by default?

No. It never looks at the machine it runs on, so its output doesn't depend on
where you run it. Anything you leave out stays in the output as a condition on its
rule, for example `arch:amd64,x32` or `kernel>=4.8`. To evaluate for this machine,
pass its values: `-a "$(uname -m)"` and `-k "$(uname -r)"`. For the capabilities of
a container, see the next entry.

## Can I use the output of `capsh --print`?

Yes, for the bounding set. Capability names are case-insensitive and the `CAP_`
prefix is optional, so the lowercase `cap_chown` form works:

```
seccat --caps "$(capsh --print | sed -n 's/^Bounding set =//p')" -a "$(uname -m)" docker.json
```

An empty bounding set, which `capsh` prints for a container with every capability
dropped, is the empty set, the same as `--caps none`.

## Does it work with Kubernetes seccomp profiles?

Yes, for `Localhost` profiles: Kubernetes reads the same JSON format. The three
examples in the Kubernetes documentation (`audit.json`, `violation.json` and
`fine-grained.json`) load without warnings and convert back to the same
behavior.

```
curl -sSfL https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/pods/security/seccomp/profiles/fine-grained.json | seccat
```

`RuntimeDefault` is not a file: it is built into the container runtime, so there
is nothing to point seccat at unless you have that runtime's profile. YAML
`SeccompProfile` objects from the Security Profiles Operator are not tested;
seccat reads JSON.

## Can I read the profile a container actually runs with?

Yes. runc and crun read the `linux.seccomp` section of the OCI bundle's
`config.json`, which is the profile after Docker or Podman filtered it for the
container. Give seccat that file, or just that object:

```
seccat config.json
```

The filtering has already happened, so no conditions are left: `--caps`,
`--arch` and `--kernel` change nothing, while `--all` still works. A
`config.json` without a `linux.seccomp` section is an error that says so, since
the container then has no seccomp profile. That is what `runc spec` and
`crun spec` write by default.

## How do I check a release?

The release comes with a `SHA256SUMS` file:

```
sha256sum -c SHA256SUMS --ignore-missing
```

That catches a corrupted download, but the file comes from the same page, so it
doesn't prove the release is genuine. To check that, build the same tag yourself
with the same Go version, which `go version -m seccat-linux-amd64` shows,
and compare:

```
git checkout v0.1.0
make release
cat dist/SHA256SUMS
```

The binaries are static and don't depend on where or by whom they are built, so
the same commit and Go version give the same files.

## What does seccat not model?

Docker and Podman turn a profile into the OCI `linux.seccomp` section that runc
and crun read, using the container's capabilities, the host architecture and the
host kernel. `--caps`, `--arch` and `--kernel` follow that step. Not modeled:

- When several remaining rules match one call, libseccomp decides which action wins.
  seccat keeps their order, which it can depend on; it doesn't predict the result.
- runc returns `ENOSYS`, instead of the default action, for syscalls numbered above
  the largest one any rule of the profile names, for each architecture. It does not
  when the default action is `ALLOW`, `LOG` or `TRACE`, or when the profile's default
  errno is already `ENOSYS`. crun does not do this.
- libseccomp skips syscall names it doesn't know for the target architecture.
- Argument conditions are shown, not evaluated. See the next entry for how they can
  surprise you.

## What should I watch for in argument conditions?

Three things bit real profiles. The tests were done with libseccomp, loaded with
`setpriv` as in [tools/README.md](tools/README.md), not with a container runtime.

- **Seccomp compares 64 bits, the kernel reads 32.** A syscall parameter declared `int`
  or `unsigned int`, such as every argument of `socket` and the argument of `personality`,
  uses only the low 32 bits of the register. `socket(0x100000028, SOCK_STREAM, 0)` is not
  equal to 40 for the filter, but the kernel opens an `AF_VSOCK` socket. So:
  - an allow with `==`, `<` or `<=` is safe: a value with high bits set doesn't match and
    gets the default action;
  - a deny with `==`, an allow with `!=`, `>` or `>=`, and any deny with an inequality, can
    be stepped around. Mask the low half instead: `arg0&0xffffffff==40`
    (`SCMP_CMP_MASKED_EQ`, mask in `value`, datum in `valueTwo`).
  - Podman's default profile had this for the `AF_VSOCK` and `NETLINK_AUDIT` denials:
    [container-libs#1248](https://github.com/podman-container-tools/container-libs/issues/1248).
    Docker's has only allowlists and `clone`'s mask, which are not affected.
- **Overlapping rules can depend on their order in the profile.** With
  `ERRNO arg0&0xffffffff==40` listed before a broader `ALLOW arg0!=40`, the deny wins; listed
  after, `socket(0x100000028, ...)` was allowed in the test. Other overlaps I tried
  (`>`, `>=`, an unconditional rule) did not depend on it, but I don't know the full rule.
  seccat keeps the order of a syscall's rules in its text output and in `--json`, and sorts
  only by syscall name. Older versions sorted whole lines, so the text of such a profile
  could compile to a different filter than the JSON it came from.
- **An unconditional rule next to conditional ones of another action** makes libseccomp drop
  or ignore the conditional ones, depending on which came first. A draft hardened profile
  had `socketpair` fail for every family, `AF_UNIX` included, that way.

Two limits of masks: libseccomp accepts one comparison per argument in a rule, so "masked
and not equal" can't be one rule, and `socketcall` (x86 and some other architectures) takes
the family through a pointer, which no argument rule can see.

## Does it run on macOS or Windows?

No, seccat builds only on Linux.

# seccat

[![CI](https://github.com/ricardobranco777/seccat/actions/workflows/ci.yml/badge.svg)](https://github.com/ricardobranco777/seccat/actions/workflows/ci.yml)

seccat defines a line-oriented intermediate language for seccomp profile JSON.
In this form, the profiles of container runtimes such as Docker and Podman can be
studied and compared with standard text tools such as `grep` and `diff`, and
edited and converted back into JSON that behaves the same.

A seccomp profile is JSON, and what it allows depends on the container. Some
rules apply only with a capability such as `CAP_SYS_ADMIN`, or on one
architecture, or from a given kernel version. Docker's default profile is 1,225
lines, and a single rule takes 22 of them (shown here compacted):

```json
{
  "names": ["clone"],
  "action": "SCMP_ACT_ALLOW",
  "args": [{"index": 0, "value": 2114060288, "op": "SCMP_CMP_MASKED_EQ"}],
  "excludes": {"caps": ["CAP_SYS_ADMIN"], "arches": ["s390", "s390x"]}
}
```

seccat writes that rule as one line, with the flag names spelled out:

```
clone	ALLOW	arg0&(CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET)==0 && !cap:SYS_ADMIN && !arch:s390,s390x
```

You can also say which capabilities, architecture and kernel your container has.
seccat then evaluates those conditions the way Docker and Podman do before they
hand the profile to runc or crun:

```
$ seccat -c docker -a amd64 -k 6.8 docker.json | grep -w -e clone3 -e ptrace
clone3	ERRNO(ENOSYS)
ptrace	ALLOW
```

The same works on profiles straight from the Docker and Podman repositories, so
the two defaults can be compared with `diff`:

```
docker=https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json
podman=https://raw.githubusercontent.com/containers/common/main/pkg/seccomp/seccomp.json
diff <(curl -sSfL $docker | seccat -A -a amd64 -c docker -k 6.8) \
     <(curl -sSfL $podman | seccat -A -a amd64 -c podman -k 6.8)
```

A few of the 182 lines that differ:

```
< @default	ERRNO(EPERM)
> @default	ERRNO(ENOSYS)
< clone3	ERRNO(ENOSYS)
> clone3	ALLOW
< fsopen	ERRNO(EPERM)
> fsopen	ALLOW
```

More examples, and how to read this diff, are in the [FAQ](FAQ.md).

## Install

Binaries for Linux (amd64 and arm64) are on the
[releases page](https://github.com/ricardobranco777/seccat/releases), with a
`SHA256SUMS` file; download one and `chmod +x` it. The names carry no version, so the
latest is always at `releases/latest/download/seccat-linux-amd64` (or `-arm64`). Or
build it:

```
make build   # builds ./seccat
go install github.com/ricardobranco777/seccat@latest
```

seccat runs on Linux only.

## Usage

```
seccat [-c SET] [-a ARCH] [-k VERSION] [-A] [FILE|-]    # JSON -> text
seccat -j [FILE|-]                                      # text -> JSON
```

Input is a file or stdin; for a URL, `curl -s URL | seccat`. It can be a Docker
or Podman profile, or the OCI `config.json` of a container (runc and crun read
it), or just its `linux.seccomp` section; seccat recognizes which. Options may
come before or after the file name. Profiles to start with:
[moby default.json][moby], [Podman seccomp.json][podman].

- `-c`, `--caps SET`: the capabilities the container has: `docker`, `podman`,
  `none`, `all`, names such as `SYS_ADMIN`, or a mix like `docker,SYS_ADMIN`.
- `-a`, `--arch ARCH`: the architecture to evaluate for, such as `amd64` or `x86_64`.
- `-k`, `--kernel VERSION`: the kernel to evaluate for, such as `6.8` or `6.8.0-45-generic`.
- `-A`, `--all`: also list the syscalls the profile leaves to its default
  action. Needs `--arch`.
- `-j`, `--json`: convert text back to JSON.
- `--version`: print the version and exit.

seccat does not look at the machine it runs on: whatever you leave out stays in the
output as a condition on its rule. To evaluate for this machine, pass its values,
for example `-a "$(uname -m)" -k "$(uname -r)"`. The text format is described in
[FORMAT.md](FORMAT.md).

[moby]: https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json
[podman]: https://raw.githubusercontent.com/containers/common/main/pkg/seccomp/seccomp.json

## More

- [FAQ.md](FAQ.md): worked examples, how conversion and testing work, limits.
- [FORMAT.md](FORMAT.md): the text format.

## License

BSD-2-Clause. The syscall table in `third_party/libseccomp` is libseccomp's,
under the LGPL-2.1; see the notes there.

## Development

`make check` runs the linters and the tests, and CI runs it on every push and
pull request. To release, push a tag such as `v0.1.0`: the release workflow runs
the checks, builds the binaries with `make release` and publishes them. The version
comes from the git tag. `make update-golden` and `make update-syscalls` refresh the
expected test output and libseccomp's syscall table.

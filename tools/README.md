This directory has `secprobe`, `seccomp-compile` and `test.sh`, to check seccat
against real seccomp filters. `make` here builds the two programs, or `make tools`
from the top directory. They are in C and run on Linux only.

secprobe prints what the seccomp filters it inherited do to every syscall, in the
text format of [seccat](../README.md): one
`NAME<TAB>ACTION` line per syscall, sorted the way seccat sorts:

    $ ./secprobe | grep -v ALLOW
    add_key	ERRNO(EPERM)
    kexec_load	TRAP
    swapoff	KILL

The action is `ALLOW`, `ERRNO(NAME)`, `KILL` or `TRAP`. A call that hangs is
reported on stderr and left out, and so are the ones the probe can't test
(`write`, `sendmsg`, `exit_group`, `uprobe` and `uretprobe`). It does not report the
seccomp mode, `no_new_privs`, the supported actions or the filters' default
action; read those from `/proc/self/status` and `prctl(2)`.

Run inside a container, it can be compared with what seccat says the profile
does there. seccat lists syscalls of every architecture and keeps argument
conditions, so leave out what `secprobe` has no answer for (`test.sh` is stricter):

    $ docker run --rm -v $PWD/secprobe:/secprobe:ro IMAGE /secprobe > got
    $ seccat -A -a amd64 -c docker -k "$KERNEL" default.json | grep -v '^@' |
          awk -F'\t' 'NR==FNR {n[$1]; next} $1 in n && NF==2' got - > expected
    $ diff expected <(awk -F'\t' 'NF==2' got)

To probe one call with chosen arguments, give its name (or a decimal number)
and up to six arguments. They can be decimal, `0x` hex or octal, and `-1` means
all bits set; missing ones are 0. The line has the arguments as seccat
conditions, so it is a rule seccat can read:

    $ ./secprobe socket 40 1      # AF_VSOCK, SOCK_STREAM; in a default Docker container
    socket	ERRNO(EPERM)	arg0==40 && arg1==1
    $ ./secprobe personality 0xffffffff
    personality	ALLOW	arg0==4294967295

## Testing against a real filter without a container runtime

`seccomp-compile.c` compiles seccat's text to a BPF program with libseccomp, the
library runc and crun use, adding the rules in order. It reads what
`seccat -n -a ARCH -c CAPS -k KERNEL PROFILE` writes (`-n` for numbers instead of
names in the conditions), including the argument conditions. `setpriv` (util-linux
2.40 or later) loads the result, so no container, root or user namespace is needed:

    $ make seccomp-compile        # needs libseccomp's headers
    $ seccat -n -a "$(uname -m)" -c docker -k "$(uname -r)" default.json | ./seccomp-compile f.bpf
    $ setpriv --no-new-privs --seccomp-filter f.bpf ./secprobe | grep -v ALLOW

The probe never runs the calls, so any capability set can be simulated with
seccat's `-c`, whatever this process holds.

`make test-tools` at the top builds seccat and runs `test.sh`; `make test` here runs
it with the seccat already in the parent directory, or `$SECCAT`. It does this for both
reference profiles in `../testdata/` under their default capabilities, with
`CAP_SYS_ADMIN` added, with none and with all, and diffs the output of `secprobe`
against `seccat -A`. It compares only the syscalls with a single answer: not those
with a conditional rule or rules that disagree (`secprobe` probes with all arguments
set to -1), nor those of other architectures or that the probe can't test; a few
calls with chosen arguments cover the conditional ones. It also checks that a filter
compiled from one profile is caught when compared with the other.
`RUNTIMES="podman docker" ./test.sh` also checks those runtimes with the same
profiles and the image `$IMAGE` (default `busybox`), which needs network to pull it.
podman is run once with each of crun and runc that is installed (`$OCI_RUNTIMES`,
default `crun runc`), with `--runtime`.
It is not part of `make test-tools` or CI. runc answers `ENOSYS`, instead of the
profile's default action, for the syscalls newer than any the profile names, and
`test.sh` expects that when the OCI runtime is runc. It prints which one it found.

This tests libseccomp's handling of a profile, not Docker's or Podman's own
conversion of it or the extras runc adds, such as ENOSYS for newer syscalls (the
`RUNTIMES` test of `test.sh` expects that one).

## Related tools

[seccomp-tools](https://github.com/david942j/seccomp-tools) works on compiled BPF
programs: `dump` extracts the filter of a running process (it needs
`CAP_SYS_ADMIN` or `CAP_SYS_PTRACE`), `disasm` and `asm` read and write BPF, and
`emu` runs a BPF program in software for one syscall, arguments and architecture
and prints the action. `secprobe` asks the kernel instead, from inside the
container and without privileges, so it sees every filter the process inherited
stacked together. `emu` could check the BPF that `seccomp-compile` writes without
loading it.

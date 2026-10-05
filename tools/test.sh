#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Checks secprobe against real seccomp filters, with seccat as the reference.
#
# By default no container runtime is needed: each reference profile is
# evaluated by seccat for some capabilities, compiled to BPF with libseccomp
# (the library runc and crun use), loaded with setpriv, and the output
# of secprobe is compared with what seccat says. This needs libseccomp's
# headers (libseccomp-devel, libseccomp-dev), setpriv from util-linux (2.40 or
# later, for --seccomp-filter) and the seccat built in the parent directory, or
# the one in $SECCAT.
#
# Only syscalls with a single answer are compared: not those with a
# conditional rule or rules that disagree (secprobe probes with all arguments
# set to -1), nor those of other architectures, nor the ones secprobe can't
# probe. A few calls with chosen arguments check the conditional rules.
#
# RUNTIMES="podman docker" also checks those runtimes with the same profiles
# and the image $IMAGE (default busybox), which is pulled if missing. podman is
# run with each of crun and runc that is installed ($OCI_RUNTIMES). That part
# needs a container runtime and network, so it is not run by default. runc
# answers ENOSYS for the newest syscalls, which runc_enosys below accounts for.
set -eu
cd "$(dirname "$0")"

seccat=${SECCAT:-../seccat}
command -v setpriv >/dev/null || { echo "test.sh: setpriv not found" >&2; exit 2; }
[ -x "$seccat" ] || { echo "test.sh: $seccat not found, run make build" >&2; exit 2; }
make --no-print-directory secprobe seccomp-compile
arch=$(uname -m)
kernel=$(uname -r)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

# The probe can't test the calls it makes itself (see secprobe.c).
untestable="write sendmsg exit_group uprobe uretprobe"
./secprobe | cut -f1 | sort -u >"$tmp/names"

# want PROFILE CAPS: what seccat says about the syscalls with a single answer,
# in $tmp/want, and their names in $tmp/plain.
want() {
	"$seccat" -A -a "$arch" -c "$2" -k "$kernel" "$1" >"$tmp/seccat"
	awk -F'\t' 'NF > 2 || ($1 in a && a[$1] != $0) {c[$1]} {a[$1] = $0} END {for (n in c) print n}' \
		"$tmp/seccat" >"$tmp/cond"
	for n in $untestable; do echo $n; done >>"$tmp/cond"
	grep -vxFf "$tmp/cond" "$tmp/names" >"$tmp/plain" || true
	awk -F'\t' 'NR==FNR {n[$1]; next} $1 in n && !seen[$0]++' "$tmp/plain" "$tmp/seccat" >"$tmp/want"
}

# oci_runtime RT: the OCI runtime that docker uses by default, such as runc;
# empty if unknown.
oci_runtime() {
	"$1" info --format '{{.DefaultRuntime}}' 2>/dev/null || true
}

# runc_enosys PROFILE CAPS: runc answers ENOSYS, not the profile's default
# action, for the syscalls numbered above the largest one any rule of the
# profile names (libcontainer/seccomp/patchbpf/enosys_linux.go). It does so per architecture, whatever the action of the
# rules, and not when the default action is ALLOW, LOG or TRACE, or the
# profile's defaultErrnoRet is ENOSYS already. crun does not do it. Change
# $tmp/want to say so. This handles only an ERRNO default, as in the reference
# profiles (runc also does it for KILL and others), and uses the table in
# third_party/libseccomp, not the one runc was built with.
runc_enosys() {
	"$seccat" -a "$arch" -c "$2" -k "$kernel" "$1" | awk -F'\t' '!/^@/ {print $1}' >"$tmp/named"
	awk -F, -v arch="$arch" 'NR==FNR {named[$1]; next}
		/^#/ {for (i = 2; i <= NF; i++) if ($i == arch) col = i; next}
		col && $col ~ /^[0-9]+$/ {nr[$1] = $col + 0; if (($1 in named) && nr[$1] > max) max = nr[$1]}
		END {if (!col) exit 1; for (n in nr) if (nr[n] > max) print n}' \
		"$tmp/named" ../third_party/libseccomp/syscalls.csv >"$tmp/newer" ||
		{ echo "test.sh: no syscall numbers for $arch in libseccomp's table" >&2; exit 2; }
	def=$(awk -F'\t' '$1 == "@default" {print $2}' "$tmp/seccat")
	case $def in ERRNO\(*) ;; *) return ;; esac
	awk -F'\t' -v def="$def" 'NR==FNR {n[$1]; next}
		$1 in n && $2 == def {$2 = "ERRNO(ENOSYS)"} {print}' OFS='\t' "$tmp/newer" "$tmp/want" >"$tmp/want.new"
	mv "$tmp/want.new" "$tmp/want"
}

# got CMD...: what the command's secprobe output says, for the same names.
got() {
	"$@" | awk -F'\t' 'NR==FNR {n[$1]; next} $1 in n' "$tmp/plain" - >"$tmp/got"
}

report() { # name, status, output
	if [ "$2" = ok ]; then
		echo "ok   $1: $(wc -l <"$tmp/want") syscalls"
	else
		echo "FAIL $1"
		echo "$3" | head -n 20
		fail=1
	fi
}

# compare NAME: diff $tmp/want and $tmp/got, which must be the same.
compare() {
	if out=$(diff "$tmp/want" "$tmp/got"); then
		report "$1" ok
	else
		report "$1" fail "$out"
	fi
}

# compile PROFILE CAPS: write $tmp/f.bpf from the rules that apply.
compile() {
	"$seccat" -n -a "$arch" -c "$2" -k "$kernel" "$1" | ./seccomp-compile "$tmp/f.bpf"
}

# check PROFILE CAPS: compile the rules that apply with these capabilities and
# check the filter. The probe never runs the calls, so the capabilities this
# process holds don't matter.
check() {
	profile=../testdata/$1.json
	compile "$profile" "$2"
	want "$profile" "$2"
	got setpriv --no-new-privs --seccomp-filter "$tmp/f.bpf" ./secprobe
	compare "$1 caps=$2"
}

# The default sets of Docker and of Podman, each with CAP_SYS_ADMIN added, none
# and all of them.
for caps in docker docker,SYS_ADMIN none all; do check docker $caps; done
for caps in podman podman,SYS_ADMIN none all; do check podman $caps; done

# Calls with chosen arguments, which the comparison above leaves out: PROFILE
# CAPS, then pairs of "NAME ARGS" and the action it must get.
probes() {
	compile "../testdata/$1.json" "$2"
	shift 2
	while [ $# -gt 0 ]; do
		line=$(setpriv --no-new-privs --seccomp-filter "$tmp/f.bpf" ./secprobe $1 | cut -f1,2)
		if [ "$line" = "$(echo "$1" | cut -d' ' -f1)	$2" ]; then
			echo "ok   $1 -> $2"
		else
			echo "FAIL $1 -> $2, got: $line"
			fail=1
		fi
		shift 2
	done
}
probes docker docker "socket 40 1" ERRNO\(EPERM\) "socket 2 1" ALLOW \
	"clone 0x10000000" ERRNO\(EPERM\) "clone 0" ALLOW \
	"personality 8" ALLOW "personality 5" ERRNO\(EPERM\)
probes docker docker,SYS_ADMIN "clone 0x10000000" ALLOW

# Control: a filter checked against the wrong profile must be caught.
compile ../testdata/docker.json docker
want ../testdata/podman.json docker
got setpriv --no-new-privs --seccomp-filter "$tmp/f.bpf" ./secprobe
if out=$(diff "$tmp/want" "$tmp/got"); then
	report "control (docker filter, podman profile)" fail "expected differences, got none"
else
	echo "ok   control (docker filter, podman profile): $(echo "$out" | grep -c '^[<>]') differing lines"
fi

# runtime_test OCI RT [OPTION...]: run the image with the container runtime RT
# (and options such as --runtime) for each profile, and compare. OCI is the
# OCI runtime that RT ends up with.
runtime_test() {
	oci=$1 rt=$2
	shift 2
	for profile in docker podman; do
		file=$(cd ../testdata && pwd)/$profile.json
		want "$file" "$profile"
		[ "$oci" != runc ] || runc_enosys "$file" "$profile"
		got "$rt" "$@" run --rm --security-opt "seccomp=$file" \
			-v "$PWD/secprobe:/secprobe:ro,z" "${IMAGE:-busybox}" /secprobe
		compare "${rt##*/} (${oci:-unknown runtime}) with $profile.json"
	done
}

# podman is run with each OCI runtime in $OCI_RUNTIMES (default crun and runc)
# that is installed, as podman accepts --runtime.
for rt in ${RUNTIMES:-}; do
	case ${rt##*/} in
	podman)
		for oci in ${OCI_RUNTIMES:-crun runc}; do
			if path=$(command -v "$oci"); then
				runtime_test "$oci" "$rt" --runtime "$path"
			else
				echo "skip ${rt##*/} with $oci: not found"
			fi
		done ;;
	*) runtime_test "$(oci_runtime "$rt")" "$rt" ;;
	esac
done

exit $fail

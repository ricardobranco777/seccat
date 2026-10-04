# SPDX-License-Identifier: BSD-2-Clause
#
# Normalizes a Docker/Podman seccomp profile so that two profiles can be compared
# with diff: a header line, then one compact line per syscall name per entry.
# Keys are sorted (use -S), empty fields are dropped, lists that are sets are
# sorted, and a name listed in an entry becomes one line, so entry order and
# grouping no longer matter. Sort the output.
#
#   norm() { jq -S -c -f contrib/normalize.jq "$@" | sort; }
#   diff <(norm in.json) <(seccat in.json | seccat -j | norm)
#
# Podman's errno and defaultErrno strings are dropped in favor of the numbers
# beside them. A profile that has only the strings differs from its round trip.

def clean: with_entries(select(.value != null and .value != [] and .value != "" and .value != {}));

def filter:
  (. // {})
  | (if .caps then .caps |= (map(ascii_upcase | ltrimstr("CAP_")) | sort) else . end)
  | (if .arches then .arches |= sort else . end)
  | clean;

# valueTwo only means something for masked comparisons.
def arg: if .op == "SCMP_CMP_MASKED_EQ" then .valueTwo //= 0 else del(.valueTwo) end;

( del(.syscalls, .defaultErrno)
  | .archMap |= ((. // []) | map(clean))
  | clean
  | {header: .} ),
( (.syscalls // [])[]
  | . as $e
  | ($e.names // [$e.name])[] as $n
  | $e
  | del(.names, .name, .errno)
  | .includes |= filter
  | .excludes |= filter
  | .args |= ((. // []) | map(arg) | sort_by([.index, .op, .value]))
  | clean
  | . + {name: $n} )

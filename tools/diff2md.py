#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Turn a diff of two normalized seccomp profiles into a 3-column Markdown table.

Columns: syscall, left side rules, right side rules.
Rows are keyed by syscall name, so lines that diff happened to pair up
positionally are not mixed together. Multiple rules for one syscall are
stacked in the cell with <br>. Accepts normal (`<`/`>`) or unified (`-`/`+`) diffs.

A side with no differing rule for a syscall gets the action that side falls back to,
the `@default` line of the diff, as plain text (a rule is a code span). That is right when the syscall has no
rule on that side, or its rule is the default (the usual case in `seccat -A` output).
diff hides lines that are identical on both sides, so it can be wrong if a hidden
rule is not the default. If the two defaults don't differ, the diff has no `@default`
line and the cell stays empty.

Usage: diff2md.py [DIFF]    # reads stdin if DIFF is omitted
"""
import re
import sys

HUNK_NORMAL = re.compile(r"^\d+(,\d+)?[acd]\d+(,\d+)?$")


def parse(lines):
    rows = {}  # name -> ([left rules], [right rules])
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith(("---", "+++", "@@")) or HUNK_NORMAL.match(line):
            continue
        if line[:1] in ("<", "-"):
            side = 0
        elif line[:1] in (">", "+"):
            side = 1
        else:
            continue
        fields = line[1:].split(None, 1)
        if not fields:
            continue
        name = fields[0]
        rule = " ".join(fields[1].split()) if len(fields) > 1 else ""
        rows.setdefault(name, ([], []))[side].append(rule)
    return rows


def cell(rules, default=""):
    """One code span per rule, one rule per line (<br> works in GitHub tables).
    With no rules, the side's default action as plain text, if it is known."""
    if not rules and default:
        return default
    return "<br>".join("`" + r.replace("|", "\\|") + "`" for r in rules if r)


def main():
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    with src:
        rows = parse(src)
    # The defaults are the "@default" row: its left and right rules.
    defaults = [(d[0] if d else "") for d in rows.get("@default", ([], []))]
    # Markdown requires a header row; leave it blank so no names are assumed.
    print("| | | |\n|---|---|---|")
    for name, (left, right) in sorted(rows.items()):
        cells = [cell([name]), cell(left, defaults[0]), cell(right, defaults[1])]
        print("| " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()

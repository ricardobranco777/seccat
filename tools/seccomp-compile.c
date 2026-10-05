/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * seccomp-compile turns seccat's text format into a BPF program that
 * setpriv(1) and bwrap(1) can load, with libseccomp, the library runc and crun
 * use. The rules are added in the order given, as the runtimes do, so
 * libseccomp resolves overlapping rules the same way.
 *
 * It reads what "seccat -n -a ARCH -c CAPS -k KERNEL PROFILE" writes: the
 * @default line and the rules that apply there, with argument values as
 * numbers. The conditions are argN OP VALUE joined by " && ", where OP is one
 * of == != < <= > >=, and argN&MASK==VALUE. A condition on a capability,
 * architecture or kernel means that seccat wasn't told which, and is an error.
 * The other @ lines are skipped, and so are syscalls libseccomp doesn't know on
 * this architecture, as runc does.
 *
 *	seccat -n -a "$(uname -m)" -c docker -k "$(uname -r)" p.json | seccomp-compile out.bpf
 *	setpriv --no-new-privs --seccomp-filter out.bpf ./secprobe
 *
 *	cc -O2 -Wall -Wextra -o seccomp-compile seccomp-compile.c -lseccomp
 */
#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* syscalls.h is made for secprobe.c; only its errno table is used here. */
struct syscall_entry {
	int nr;
	const char *name;
};

#pragma GCC diagnostic ignored "-Wunused-variable"
#include "syscalls.h"

static int errno_number(const char *name)
{
	for (size_t i = 0; i < sizeof(errno_names) / sizeof(errno_names[0]); i++)
		if (errno_names[i] && !strcmp(errno_names[i], name))
			return i;
	return -1;
}

/* ALLOW, ERRNO, ERRNO(NAME), ERRNO(N), KILL*, TRAP, LOG, TRACE, TRACE(N) or
 * NOTIFY. A bare ERRNO is what runtimes answer with EPERM. */
static uint32_t action(int lineno, char *s)
{
	char *arg = strchr(s, '(');
	int n = 0;

	if (arg) {
		char *end = strchr(arg, ')');

		if (!end || end[1])
			errx(2, "line %d: bad action", lineno);
		*arg++ = 0;
		*end = 0;
		n = errno_number(arg);
		if (n < 0)
			n = atoi(arg);
	}
	if (!strcmp(s, "ALLOW"))
		return SCMP_ACT_ALLOW;
	if (!strcmp(s, "ERRNO"))
		return SCMP_ACT_ERRNO(arg ? n : EPERM);
	if (!strncmp(s, "KILL", 4))
		return SCMP_ACT_KILL;
	if (!strcmp(s, "TRAP"))
		return SCMP_ACT_TRAP;
	if (!strcmp(s, "LOG"))
		return SCMP_ACT_LOG;
	if (!strcmp(s, "TRACE"))
		return SCMP_ACT_TRACE(n);
	if (!strcmp(s, "NOTIFY"))
		return SCMP_ACT_NOTIFY;
	errx(2, "line %d: unknown action", lineno);
}

/* Parses one condition into cmp: argN OP VALUE or argN&MASK==VALUE. */
static void condition(int lineno, char *s, struct scmp_arg_cmp *cmp)
{
	static const struct {
		const char *text;
		enum scmp_compare op;
	} ops[] = {
	    {"==", SCMP_CMP_EQ}, {"!=", SCMP_CMP_NE}, {"<=", SCMP_CMP_LE},
	    {">=", SCMP_CMP_GE}, {"<", SCMP_CMP_LT},  {">", SCMP_CMP_GT},
	};
	char *p = s + 3, *end;
	unsigned idx;

	if (strncmp(s, "arg", 3) || *p < '0' || *p > '5')
		errx(2, "line %d: a condition seccat couldn't resolve; pass -a, -c and -k to it",
		     lineno);
	idx = *p++ - '0';
	errno = 0;
	if (*p == '&') {
		uint64_t mask = strtoull(p + 1, &end, 0);

		if (end == p + 1 || errno || strncmp(end, "==", 2))
			errx(2, "line %d: bad mask condition", lineno);
		p = end + 2;
		uint64_t v = strtoull(p, &end, 0);

		if (end == p || *end || errno)
			errx(2, "line %d: bad number", lineno);
		*cmp = SCMP_CMP(idx, SCMP_CMP_MASKED_EQ, mask, v);
		return;
	}
	for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		size_t n = strlen(ops[i].text);

		if (!strncmp(p, ops[i].text, n)) {
			uint64_t v = strtoull(p + n, &end, 0);

			if (end == p + n || *end || errno)
				errx(2, "line %d: bad number", lineno);
			*cmp = SCMP_CMP(idx, ops[i].op, v);
			return;
		}
	}
	errx(2, "line %d: unknown operator", lineno);
}

int main(int argc, char **argv)
{
	scmp_filter_ctx ctx = NULL;
	char line[1024];
	int lineno = 0, fd, rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s OUT.bpf < rules\n", argv[0]);
		return 2;
	}
	while (fgets(line, sizeof(line), stdin)) {
		char *f[3], *nl = strchr(line, '\n');
		struct scmp_arg_cmp cmp[6];
		int nf = 0, ncmp = 0, nr;

		lineno++;
		if (nl)
			*nl = 0;
		for (char *t = strtok(line, "\t"); t && nf < 3; t = strtok(NULL, "\t"))
			f[nf++] = t;
		if (nf == 0 || f[0][0] == '#')
			continue;
		if (!strcmp(f[0], "@default")) {
			if (ctx)
				errx(2, "line %d: second @default", lineno);
			if (nf != 2)
				errx(2, "line %d: usage: @default ACTION", lineno);
			ctx = seccomp_init(action(lineno, f[1]));
			if (!ctx)
				errx(2, "line %d: seccomp_init failed", lineno);
			continue;
		}
		if (f[0][0] == '@')
			continue;
		if (!ctx)
			errx(2, "line %d: rule before @default", lineno);
		if (nf < 2)
			errx(2, "line %d: expected NAME ACTION", lineno);
		/* A third field is the conditions unless it is a comment. */
		if (nf == 3 && strncmp(f[2], "# ", 2)) {
			char *rest = f[2], *and;

			do {
				and = strstr(rest, " && ");
				if (and) {
					*and = 0;
				}
				if (ncmp == 6)
					errx(2, "line %d: too many conditions", lineno);
				condition(lineno, rest, &cmp[ncmp++]);
				rest = and + 4;
			} while (and);
		}
		nr = seccomp_syscall_resolve_name(f[0]);
		if (nr == __NR_SCMP_ERROR) {
			warnx("skipping unknown syscall %s", f[0]);
			continue;
		}
		rc = seccomp_rule_add_array(ctx, action(lineno, f[1]), nr, ncmp, cmp);
		if (rc < 0) {
			errno = -rc;
			err(1, "line %d: %s", lineno, f[0]);
		}
	}
	if (!ctx)
		errx(2, "line %d: no @default line", lineno);
	fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		err(1, "%s", argv[1]);
	if ((rc = seccomp_export_bpf(ctx, fd)) < 0) {
		errno = -rc;
		err(1, "export");
	}
	if (close(fd) < 0)
		err(1, "%s", argv[1]);
	seccomp_release(ctx);
	return 0;
}

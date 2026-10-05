/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * secprobe tells what the seccomp filters this process inherited do to each system
 * call, without running the calls. It prints seccat's text format, one
 * "NAME<TAB>ACTION" line per syscall (ALLOW, ERRNO(EPERM), KILL or TRAP), in
 * the order seccat sorts, so the output can be compared with
 * "seccat -A" using diff(1).
 *
 * For each syscall a child process stacks its own filter that returns
 * SECCOMP_RET_USER_NOTIF for that syscall number only, and calls it. When
 * several filters apply the kernel takes the most restrictive action, and
 * USER_NOTIF ranks below kill, trap and errno. So:
 *
 *  - this process, as the supervisor, gets a notification: the inherited
 *    filters allow the call. It answers with a sentinel error, so the kernel
 *    never runs the syscall, however dangerous it is.
 *  - no notification and the child gets an errno: an inherited filter
 *    returned it.
 *  - the child is killed or trapped: an inherited filter did that.
 *
 * This needs Linux 5.0 and a filter that lets the child call seccomp(2).
 * Calls that hang or can't be tested go to stderr, not into the rules.
 *
 *	make
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

struct syscall_entry {
	int nr;
	const char *name;
};

#include "syscalls.h"

#define NSYSCALLS (sizeof(syscall_table) / sizeof(syscall_table[0]))
#define NERRNOS (sizeof(errno_names) / sizeof(errno_names[0]))

/* The errno the supervisor answers with. A notified syscall never runs; the
 * child sees this instead. */
#define SENTINEL 777

enum vkind { V_ALLOWED, V_ERRNO, V_KILL, V_TRAP, V_HANG, V_UNKNOWN };

struct verdict {
	enum vkind kind;
	int err;	/* V_ERRNO only */
	char text[320]; /* V_UNKNOWN only: the reason */
};

/* How long one syscall may take before it counts as a hang. */
#define PROBE_TIMEOUT_MS 3000

/* The syscalls the child itself makes after installing its filter: handing
 * the listener over, printing the answer, exiting. A notification for one of
 * these would be answered with the sentinel and break the child, so they
 * can't be tested. uprobe and uretprobe are skipped because the kernel
 * handles them before seccomp runs. */
static const char *const untestable[] = {
    "write", "sendmsg", "exit_group", "uprobe", "uretprobe",
};

typedef uint64_t args_t[6];

#define M1 UINT64_MAX
#define MINUS_ONE {M1, M1, M1, M1, M1, M1}

static const char *errname(int e)
{
	static char buf[32];

	if (e == 0)
		return "ok";
	if ((size_t)e < NERRNOS && errno_names[e])
		return errno_names[e];
	snprintf(buf, sizeof(buf), "errno %d", e);
	return buf;
}

/* ---- the child ---- */

/* A filter that returns TRAP delivers SIGSYS; a filter that kills does not.
 * Telling the parent apart is the whole point of the handler. */
static void on_sigsys(int sig)
{
	(void)sig;
	static const char msg[] = "trap\n";

	(void)!write(1, msg, sizeof(msg) - 1);
	_exit(0);
}

static int seccomp_call(unsigned op, unsigned flags, void *arg)
{
	return syscall(SYS_seccomp, op, flags, arg);
}

/* Installs the notifying filter for one syscall, hands the listener to the
 * parent, calls the syscall and prints what came back. Only async-signal-safe
 * calls after the fork, and nothing that would itself trip the filter. */
static void child_main(int sock, int nr, const args_t a)
{
	struct sock_filter prog[] = {
	    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0), /* seccomp_data.nr */
	    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
	    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog fprog = {.len = 4, .filter = prog};
	struct sigaction sa = {.sa_handler = on_sigsys};
	char out[64];
	int fd, e, n;

	sigaction(SIGSYS, &sa, NULL);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		n = snprintf(out, sizeof(out), "install=no_new_privs: %s\n", errname(errno));
		(void)!write(1, out, n);
		_exit(0);
	}
	fd = seccomp_call(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
	if (fd < 0) {
		n = snprintf(out, sizeof(out), "install=seccomp: %s\n", errname(errno));
		(void)!write(1, out, n);
		_exit(0);
	}

	union {
		struct cmsghdr h;
		char buf[CMSG_SPACE(sizeof(int))];
	} u;
	char byte = 0;
	struct iovec iov = {&byte, 1};
	struct msghdr msg = {.msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = u.buf,
			     .msg_controllen = sizeof(u.buf)};
	struct cmsghdr *c;

	memset(&u, 0, sizeof(u));
	c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &fd, sizeof(int));
	if (sendmsg(sock, &msg, 0) < 0) {
		n = snprintf(out, sizeof(out), "install=send: %s\n", errname(errno));
		(void)!write(1, out, n);
		_exit(0);
	}

	errno = 0;
	if (syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]) == -1)
		e = errno;
	else
		e = 0;
	n = snprintf(out, sizeof(out), "errno=%d\n", e);
	(void)!write(1, out, n);
	_exit(0);
}

/* ---- the supervisor ---- */

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Receives the child's listener fd, or -1 if the child exited without
 * installing a filter. */
static int recv_listener(int sock, int64_t deadline)
{
	union {
		struct cmsghdr h;
		char buf[CMSG_SPACE(sizeof(int))];
	} u;
	char byte;
	struct iovec iov = {&byte, 1};
	struct msghdr msg = {.msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = u.buf,
			     .msg_controllen = sizeof(u.buf)};
	struct pollfd p = {.fd = sock, .events = POLLIN};
	struct cmsghdr *c;
	int fd;

	for (;;) {
		int64_t left = deadline - now_ms();

		if (left < 0)
			left = 0;
		if (poll(&p, 1, (int)left) > 0)
			break;
		if (errno != EINTR)
			return -1;
	}
	if (recvmsg(sock, &msg, 0) <= 0)
		return -1;
	c = CMSG_FIRSTHDR(&msg);
	if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
		return -1;
	memcpy(&fd, CMSG_DATA(c), sizeof(int));
	return fd;
}

/* Answers every notification with the sentinel error until the child is gone
 * or the deadline passes. Returns whether anything was notified. */
static int supervise(int fd, int64_t deadline)
{
	int notified = 0;

	for (;;) {
		struct pollfd p = {.fd = fd, .events = POLLIN};
		int64_t left = deadline - now_ms();
		int r;

		if (left <= 0)
			return notified; /* hang: the caller kills the child */
		r = poll(&p, 1, (int)left);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return notified;
		}
		if (r == 0 || !(p.revents & POLLIN))
			return notified; /* timeout, or hangup: the child is gone */

		struct seccomp_notif req;
		struct seccomp_notif_resp resp;

		memset(&req, 0, sizeof(req)); /* must be zeroed */
		if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
			if (errno == ENOENT)
				continue; /* the caller was killed meanwhile */
			return notified;
		}
		notified = 1;
		memset(&resp, 0, sizeof(resp));
		resp.id = req.id;
		resp.error = -SENTINEL;
		(void)ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
	}
}

static void unknown(struct verdict *v, const char *fmt, const char *arg)
{
	v->kind = V_UNKNOWN;
	snprintf(v->text, sizeof(v->text), fmt, arg);
}

/* Calls one syscall in a child that has our notifying filter installed and
 * says what the inherited filters did. */
static void probe(int nr, const args_t a, struct verdict *v)
{
	int sock[2], outp[2];
	char out[256];
	size_t len = 0;
	int status, listener, notified = 0, timed_out = 0;
	int64_t deadline = now_ms() + PROBE_TIMEOUT_MS;
	pid_t pid;
	ssize_t n;

	memset(v, 0, sizeof(*v));
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sock) < 0 ||
	    pipe2(outp, O_CLOEXEC) < 0) {
		unknown(v, "%s", strerror(errno));
		return;
	}
	fflush(NULL);
	pid = fork();
	if (pid < 0) {
		unknown(v, "%s", strerror(errno));
		return;
	}
	if (pid == 0) {
		dup2(outp[1], 1);
		child_main(sock[1], nr, a);
	}
	close(sock[1]);
	close(outp[1]);

	listener = recv_listener(sock[0], deadline);
	if (listener >= 0) {
		notified = supervise(listener, deadline);
		close(listener);
	}
	if (now_ms() >= deadline) {
		timed_out = 1;
		kill(pid, SIGKILL);
	}
	waitpid(pid, &status, 0);
	while (len < sizeof(out) - 1 && (n = read(outp[0], out + len, sizeof(out) - 1 - len)) > 0)
		len += n;
	out[len] = 0;
	while (len && isspace((unsigned char)out[len - 1]))
		out[--len] = 0;
	close(sock[0]);
	close(outp[0]);

	if (WIFSIGNALED(status)) {
		if (timed_out)
			v->kind = V_HANG;
		else if (WTERMSIG(status) == SIGSYS)
			v->kind = V_KILL;
		else {
			snprintf(v->text, sizeof(v->text), "died from %s",
				 strsignal(WTERMSIG(status)));
			v->kind = V_UNKNOWN;
		}
		return;
	}
	if (!strcmp(out, "trap"))
		v->kind = V_TRAP;
	else if (!strncmp(out, "install=", 8))
		unknown(v, "%s", out);
	else if (!strncmp(out, "errno=", 6)) {
		int e = atoi(out + 6);

		if (notified && e == SENTINEL)
			v->kind = V_ALLOWED;
		else if (notified)
			unknown(v, "notified, but the child saw %s", out);
		else {
			v->kind = V_ERRNO;
			v->err = e;
		}
	} else
		unknown(v, "%s", out);
}

/* ---- the sweep ---- */

static int by_nr(const void *a, const void *b)
{
	const struct syscall_entry *x = a, *y = b;

	return (x->nr > y->nr) - (x->nr < y->nr);
}

static int lookup(const char *name)
{
	for (size_t i = 0; i < NSYSCALLS; i++)
		if (!strcmp(syscall_table[i].name, name))
			return syscall_table[i].nr;
	return -1;
}

static int is_untestable(const char *name)
{
	for (size_t i = 0; i < sizeof(untestable) / sizeof(untestable[0]); i++)
		if (!strcmp(untestable[i], name))
			return 1;
	return 0;
}

static int untestable_nr(int nr)
{
	for (size_t i = 0; i < sizeof(untestable) / sizeof(untestable[0]); i++)
		if (lookup(untestable[i]) == nr)
			return 1;
	return 0;
}

/* A syscall name from the table, or a plain decimal number for calls the
 * headers don't know. Returns -1 if it is neither. */
static int parse_nr(const char *s)
{
	char *end;
	long n;

	if (lookup(s) >= 0)
		return lookup(s);
	n = strtol(s, &end, 10);
	if (*s && !*end && n >= 0 && n <= INT_MAX)
		return n;
	return -1;
}

/* Decimal, 0x hex or 0 octal; a leading minus gives the two's complement, so
 * -1 is all bits set. Returns 0 on success, -1 on junk. */
static int parse_arg(const char *s, uint64_t *out)
{
	char *end;

	errno = 0;
	if (*s == '-')
		*out = (uint64_t)strtoll(s, &end, 0);
	else
		*out = strtoull(s, &end, 0);
	return (!*s || *end || errno) ? -1 : 0;
}

/* Returns 1 if our own filter can't be installed, as then nothing can be
 * tested. */
static int selfcheck(void)
{
	const args_t minus_one = MINUS_ONE;
	struct verdict v;

	probe(lookup("getpid"), minus_one, &v);
	if (v.kind == V_UNKNOWN) {
		warnx("seccomp: %s", v.text);
		return 1;
	}
	return 0;
}

/* seccat orders lines with digit runs compared by value, so that "arg0==8"
 * comes before "arg0==10". */
static int natural_cmp(const void *pa, const void *pb)
{
	const unsigned char *a = *(unsigned char *const *)pa, *b = *(unsigned char *const *)pb;

	while (*a && *b) {
		if (isdigit(*a) && isdigit(*b)) {
			const unsigned char *ea = a, *eb = b;
			size_t la, lb;

			while (isdigit(*ea))
				ea++;
			while (isdigit(*eb))
				eb++;
			la = ea - a;
			lb = eb - b;
			while (la > 1 && *a == '0')
				a++, la--;
			while (lb > 1 && *b == '0')
				b++, lb--;
			if (la != lb)
				return la < lb ? -1 : 1;
			if (memcmp(a, b, la))
				return memcmp(a, b, la);
			a = ea;
			b = eb;
			continue;
		}
		if (*a != *b)
			return *a - *b;
		a++, b++;
	}
	return *a ? 1 : *b ? -1 : 0;
}

/* The rule that says what a verdict was: NAME, ACTION and, for a call made
 * with chosen arguments, the conditions on its first nargs arguments. Returns
 * a malloc'd line, or NULL (after saying why on stderr) for a call that has
 * no action to print. */
static char *rule(const char *name, const args_t a, int nargs, const struct verdict *v)
{
	char act[64], cond[6 * 40] = "", *line;
	size_t n = 0;

	switch (v->kind) {
	case V_ALLOWED:
		strcpy(act, "ALLOW");
		break;
	case V_ERRNO:
		if (v->err > 0 && (size_t)v->err < NERRNOS && errno_names[v->err])
			snprintf(act, sizeof(act), "ERRNO(%s)", errno_names[v->err]);
		else
			snprintf(act, sizeof(act), "ERRNO(%d)", v->err);
		break;
	case V_KILL:
		strcpy(act, "KILL");
		break;
	case V_TRAP:
		strcpy(act, "TRAP");
		break;
	case V_HANG:
		warnx("%s: hang", name);
		return NULL;
	default:
		warnx("%s: %s", name, v->text);
		return NULL;
	}
	for (int i = 0; i < nargs; i++)
		n += snprintf(cond + n, sizeof(cond) - n,
			      a[i] > UINT32_MAX ? "%sarg%d==%#llx" : "%sarg%d==%llu",
			      i ? " && " : "\t", i, (unsigned long long)a[i]);
	if (asprintf(&line, "%s\t%s%s", name, act, cond) < 0)
		err(1, "asprintf");
	return line;
}

static int run(void)
{
	const args_t minus_one = MINUS_ONE;
	struct verdict v;
	char **lines = NULL;
	size_t n = 0, cap = 0;

	for (size_t i = 0; i < NSYSCALLS; i++) {
		const char *name = syscall_table[i].name;
		char *line;

		if (is_untestable(name))
			continue;
		probe(syscall_table[i].nr, minus_one, &v);
		if (!(line = rule(name, minus_one, 0, &v)))
			continue;
		if (n == cap &&
		    !(lines = realloc(lines, (cap = cap ? cap * 2 : 1024) * sizeof(*lines))))
			err(1, "realloc");
		lines[n++] = line;
	}
	qsort(lines, n, sizeof(*lines), natural_cmp);
	for (size_t i = 0; i < n; i++)
		puts(lines[i]);
	return 0;
}

/* Probes one call with the given arguments and prints its rule. */
static int one(int argc, char **argv)
{
	args_t a = {0};
	struct verdict v;
	char *line;
	int nr;

	if (argc > 7)
		return -1;
	nr = parse_nr(argv[0]);
	if (nr < 0)
		return -1;
	for (int i = 1; i < argc; i++)
		if (parse_arg(argv[i], &a[i - 1]) < 0)
			return -1;
	if (selfcheck())
		return 1;
	if (untestable_nr(nr)) {
		warnx("%s: untestable", argv[0]);
		return 0;
	}
	probe(nr, a, &v);
	if ((line = rule(argv[0], a, argc - 1, &v)))
		puts(line);
	return 0;
}

static int usage(const char *prog)
{
	fprintf(stderr, "usage: %s\n       %s NAME [ARG...]\n", prog, prog);
	return 2;
}

int main(int argc, char **argv)
{
	int r;

	qsort(syscall_table, NSYSCALLS, sizeof(syscall_table[0]), by_nr);
	if (argc == 1)
		return selfcheck() ?: run();
	if (argv[1][0] == '-' && argv[1][1])
		return usage(argv[0]);
	r = one(argc - 1, argv + 1);
	return r < 0 ? usage(argv[0]) : r;
}


#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/types.h>

/* Get all of the CLONE_NEW* flags. */
#include "namespace.h"

/* Synchronisation values. */
enum sync_t {
	SYNC_USERMAP_PLS = 0x40,	/* Request parent to map our users. */
	SYNC_USERMAP_ACK = 0x41,	/* Mapping finished by the parent. */
	SYNC_RECVPID_PLS = 0x42,	/* Tell parent we're sending the PID. */
	SYNC_RECVPID_ACK = 0x43,	/* PID was correctly received by parent. */
	SYNC_GRANDCHILD = 0x44,	/* The grandchild is ready to run. */
	SYNC_CHILD_READY = 0x45,	/* The child or grandchild is ready to return. */
};

/*
 * Synchronisation value for cgroup namespace setup.
 * The same constant is defined in process_linux.go as "createCgroupns".
 */
#define CREATECGROUPNS 0x80

/* longjmp() arguments. */
#define JUMP_PARENT 0x00
#define JUMP_CHILD  0xA0
#define JUMP_INIT   0xA1

/* Assume the stack grows down, so arguments should be above it. */
struct clone_t {
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place
	 */
	char stack[4096] __attribute__ ((aligned(16)));
	char stack_ptr[0];

	/* There's two children. This is used to execute the different code. */
	jmp_buf *env;
	int jmpval;
};

struct nlconfig_t {
	char *data;

	/* Process settings. */
	uint32_t cloneflags;
	char *oom_score_adj;
	size_t oom_score_adj_len;

	/* User namespace settings. */
	char *uidmap;
	size_t uidmap_len;
	char *gidmap;
	size_t gidmap_len;
	char *namespaces;
	size_t namespaces_len;
	uint8_t is_setgroup;

	/* Rootless container settings. */
	uint8_t is_rootless_euid;	/* boolean */
	char *uidmappath;
	size_t uidmappath_len;
	char *gidmappath;
	size_t gidmappath_len;
};

#define PANIC   "panic"
#define FATAL   "fatal"
#define ERROR   "error"
#define WARNING "warning"
#define INFO    "info"
#define DEBUG   "debug"

static int logfd = -1;

/*
 * List of netlink message types sent to us as part of bootstrapping the init.
 * These constants are defined in libcontainer/message_linux.go.
 */
#define INIT_MSG			62000
#define CLONE_FLAGS_ATTR	27281
#define NS_PATHS_ATTR		27282
#define UIDMAP_ATTR			27283
#define GIDMAP_ATTR			27284
#define SETGROUP_ATTR		27285
#define OOM_SCORE_ADJ_ATTR	27286
#define ROOTLESS_EUID_ATTR	27287
#define UIDMAPPATH_ATTR	    27288
#define GIDMAPPATH_ATTR	    27289

/*
 * Use the raw syscall for versions of glibc which don't include a function for
 * it, namely (glibc 2.12).
 */
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#	define _GNU_SOURCE
#	include "syscall.h"
#	if !defined(SYS_setns) && defined(__NR_setns)
#		define SYS_setns __NR_setns
#	endif

#ifndef SYS_setns
#	error "setns(2) syscall not supported by glibc version"
#endif

int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif

static void write_log_with_info(const char *level, const char *function, int line, const char *format, ...)
{
	char message[1024] = {};

	va_list args;

	if (logfd < 0 || level == NULL)
		return;

	va_start(args, format);
	if (vsnprintf(message, sizeof(message), format, args) < 0)
		goto done;

	dprintf(logfd, "{\"level\":\"%s\", \"msg\": \"%s:%d %s\"}\n", level, function, line, message);
done:
	va_end(args);
}

#define write_log(level, fmt, ...) \
	write_log_with_info((level), __FUNCTION__, __LINE__, (fmt), ##__VA_ARGS__)

/* XXX: This is ugly. */
static int syncfd = -1;

#define bail(fmt, ...)                                       \
	do {                                                       \
		write_log(FATAL, "nsenter: " fmt ": %m", ##__VA_ARGS__); \
		exit(1);                                                 \
	} while(0)

static int write_file(char *data, size_t data_len, char *pathfmt, ...)
{
	int fd, len, ret = 0;
	char path[PATH_MAX];

	va_list ap;
	va_start(ap, pathfmt);
	len = vsnprintf(path, PATH_MAX, pathfmt, ap);
	va_end(ap);
	if (len < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		return -1;
	}

	len = write(fd, data, data_len);
	if (len != data_len) {
		ret = -1;
		goto out;
	}

 out:
	close(fd);
	return ret;
}

enum policy_t {
	SETGROUPS_DEFAULT = 0,
	SETGROUPS_ALLOW,
	SETGROUPS_DENY,
};

/* This *must* be called before we touch gid_map. */
static void update_setgroups(int pid, enum policy_t setgroup)
{
	char *policy;

	switch (setgroup) {
	case SETGROUPS_ALLOW:
		policy = "allow";
		break;
	case SETGROUPS_DENY:
		policy = "deny";
		break;
	case SETGROUPS_DEFAULT:
	default:
		/* Nothing to do. */
		return;
	}

	if (write_file(policy, strlen(policy), "/proc/%d/setgroups", pid) < 0) {
		/*
		 * If the kernel is too old to support /proc/pid/setgroups,
		 * open(2) or write(2) will return ENOENT. This is fine.
		 */
		if (errno != ENOENT)
			bail("failed to write '%s' to /proc/%d/setgroups", policy, pid);
	}
}

static int try_mapping_tool(const char *app, int pid, char *map, size_t map_len)
{
	int child;

	/*
	 * If @app is NULL, execve will segfault. Just check it here and bail (if
	 * we're in this path, the caller is already getting desperate and there
	 * isn't a backup to this failing). This usually would be a configuration
	 * or programming issue.
	 */
	if (!app)
		bail("mapping tool not present");

	child = fork();
	if (child < 0)
		bail("failed to fork");

	if (!child) {
#define MAX_ARGV 20
		char *argv[MAX_ARGV];
		char *envp[] = { NULL };
		char pid_fmt[16];
		int argc = 0;
		char *next;

		snprintf(pid_fmt, 16, "%d", pid);

		argv[argc++] = (char *)app;
		argv[argc++] = pid_fmt;
		write_log(DEBUG, "child app :%s  and pid  %d", (char *)app,  pid_fmt);
		/*
		 * Convert the map string into a list of argument that
		 * newuidmap/newgidmap can understand.
		 */

		while (argc < MAX_ARGV) {
			if (*map == '\0') {
				argv[argc++] = NULL;
				break;
			}
			argv[argc++] = map;
			next = strpbrk(map, "\n ");
			if (next == NULL)
				break;
			*next++ = '\0';
			map = next + strspn(next, "\n ");
		}

		execve(app, argv, envp);
		bail("failed to execv");
	} else {
		int status;

		while (true) {
			if (waitpid(child, &status, 0) < 0) {
				if (errno == EINTR)
					continue;
				bail("failed to waitpid");
			}
			if (WIFEXITED(status) || WIFSIGNALED(status))
				return WEXITSTATUS(status);
		}
	}

	return -1;
}

static void update_uidmap(const char *path, int pid, char *map, size_t map_len)
{
	if (map == NULL || map_len <= 0)
		return;

	if (write_file(map, map_len, "/proc/%d/uid_map", pid) < 0) {
		if (errno != EPERM)
			bail("failed to update /proc/%d/uid_map", pid);
		if (try_mapping_tool(path, pid, map, map_len))
			bail("failed to use newuid map on %d", pid);
	}
}

static void update_gidmap(const char *path, int pid, char *map, size_t map_len)
{
	if (map == NULL || map_len <= 0)
		return;

	if (write_file(map, map_len, "/proc/%d/gid_map", pid) < 0) {
		if (errno != EPERM)
			bail("failed to update /proc/%d/gid_map", pid);
		if (try_mapping_tool(path, pid, map, map_len))
			bail("failed to use newgid map on %d", pid);
	}
}

static void update_oom_score_adj(char *data, size_t len)
{
	if (data == NULL || len <= 0)
		return;

	if (write_file(data, len, "/proc/self/oom_score_adj") < 0)
		bail("failed to update /proc/self/oom_score_adj");
}

/* A dummy function that just jumps to the given jumpval. */
static int child_func(void *arg) __attribute__ ((noinline));
static int child_func(void *arg)
{
	struct clone_t *ca = (struct clone_t *)arg;
	longjmp(*ca->env, ca->jmpval);
}

static int clone_parent(jmp_buf *env, int jmpval) __attribute__ ((noinline));
static int clone_parent(jmp_buf *env, int jmpval)
{
	struct clone_t ca = {
		.env = env,
		.jmpval = jmpval,
	};

	return clone(child_func, ca.stack_ptr, CLONE_PARENT | SIGCHLD, &ca);
}

/*
 * Gets the init pipe fd from the environment, which is used to read the
 * bootstrap data and tell the parent what the new pid is after we finish
 * setting up the environment.
 */
static int initpipe(void)
{
	int pipenum;
	char *initpipe, *endptr;

	initpipe = getenv("_LIBCONTAINER_INITPIPE");
	if (initpipe == NULL || *initpipe == '\0')
		return -1;

	pipenum = strtol(initpipe, &endptr, 10);
	if (*endptr != '\0')
		bail("unable to parse _LIBCONTAINER_INITPIPE");

	return pipenum;
}

static void setup_logpipe(void)
{
	char *logpipe, *endptr;

	logpipe = getenv("_LIBCONTAINER_LOGPIPE");
	if (logpipe == NULL || *logpipe == '\0') {
		return;
	}

	logfd = strtol(logpipe, &endptr, 10);
	if (logpipe == endptr || *endptr != '\0') {
		fprintf(stderr, "unable to parse _LIBCONTAINER_LOGPIPE, value: %s\n", logpipe);
		/* It is too early to use bail */
		exit(1);
	}
}

/* Returns the clone(2) flag for a namespace, given the name of a namespace. */
static int nsflag(char *name)
{
	if (!strcmp(name, "cgroup"))
		return CLONE_NEWCGROUP;
	else if (!strcmp(name, "ipc"))
		return CLONE_NEWIPC;
	else if (!strcmp(name, "mnt"))
		return CLONE_NEWNS;
	else if (!strcmp(name, "net"))
		return CLONE_NEWNET;
	else if (!strcmp(name, "pid"))
		return CLONE_NEWPID;
	else if (!strcmp(name, "user"))
		return CLONE_NEWUSER;
	else if (!strcmp(name, "uts"))
		return CLONE_NEWUTS;

	/* If we don't recognise a name, fallback to 0. */
	return 0;
}

static uint32_t readint32(char *buf)
{
	return *(uint32_t *) buf;
}

static uint8_t readint8(char *buf)
{
	return *(uint8_t *) buf;
}

static void nl_parse(int fd, struct nlconfig_t *config)
{
	size_t len, size;
	struct nlmsghdr hdr;
	char *data, *current;

	/* Retrieve the netlink header. */
	len = read(fd, &hdr, NLMSG_HDRLEN);
	if (len != NLMSG_HDRLEN)
		bail("invalid netlink header length %zu", len);

	if (hdr.nlmsg_type == NLMSG_ERROR)
		bail("failed to read netlink message");

	if (hdr.nlmsg_type != INIT_MSG)
		bail("unexpected msg type %d", hdr.nlmsg_type);

	/* Retrieve data. */
	size = NLMSG_PAYLOAD(&hdr, 0);
	current = data = malloc(size);
	if (!data)
		bail("failed to allocate %zu bytes of memory for nl_payload", size);

	len = read(fd, data, size);
	if (len != size)
		bail("failed to read netlink payload, %zu != %zu", len, size);

	/* Parse the netlink payload. */
	config->data = data;
	while (current < data + size) {
		struct nlattr *nlattr = (struct nlattr *)current;
		size_t payload_len = nlattr->nla_len - NLA_HDRLEN;

		/* Advance to payload. */
		current += NLA_HDRLEN;

		/* Handle payload. */
		switch (nlattr->nla_type) {
		case CLONE_FLAGS_ATTR:
			config->cloneflags = readint32(current);
			break;
		case ROOTLESS_EUID_ATTR:
			config->is_rootless_euid = readint8(current);	/* boolean */
			break;
		case OOM_SCORE_ADJ_ATTR:
			config->oom_score_adj = current;
			config->oom_score_adj_len = payload_len;
			break;
		case NS_PATHS_ATTR:
			config->namespaces = current;
			config->namespaces_len = payload_len;
			break;
		case UIDMAP_ATTR:
			config->uidmap = current;
			config->uidmap_len = payload_len;
			break;
		case GIDMAP_ATTR:
			config->gidmap = current;
			config->gidmap_len = payload_len;
			break;
		case UIDMAPPATH_ATTR:
			config->uidmappath = current;
			config->uidmappath_len = payload_len;
			break;
		case GIDMAPPATH_ATTR:
			config->gidmappath = current;
			config->gidmappath_len = payload_len;
			break;
		case SETGROUP_ATTR:
			config->is_setgroup = readint8(current);
			break;
		default:
			bail("unknown netlink message type %d", nlattr->nla_type);
		}

		current += NLA_ALIGN(payload_len);
	}
}

void nl_free(struct nlconfig_t *config)
{
	free(config->data);
}

void join_namespaces(char *nslist)
{
	int num = 0, i;
	char *saveptr = NULL;
	char *namespace = strtok_r(nslist, ",", &saveptr);
	struct namespace_t {
		int fd;
		int ns;
		char type[PATH_MAX];
		char path[PATH_MAX];
	} *namespaces = NULL;

	if (!namespace || !strlen(namespace) || !strlen(nslist))
		bail("ns paths are empty");

	/*
	 * We have to open the file descriptors first, since after
	 * we join the mnt namespace we might no longer be able to
	 * access the paths.
	 */
	do {
		int fd;
		char *path;
		struct namespace_t *ns;

		/* Resize the namespace array. */
		namespaces = realloc(namespaces, ++num * sizeof(struct namespace_t));
		if (!namespaces)
			bail("failed to reallocate namespace array");
		ns = &namespaces[num - 1];

		/* Split 'ns:path'. */
		path = strstr(namespace, ":");
		if (!path)
			bail("failed to parse %s", namespace);
		*path++ = '\0';
		write_log(DEBUG, "join namespace %s, and type %s ",path, namespace);

		fd = open(path, O_RDONLY);
		if (fd < 0)
			bail("failed to open %s", path);

		ns->fd = fd;
		ns->ns = nsflag(namespace);
		strncpy(ns->path, path, PATH_MAX - 1);
		ns->path[PATH_MAX - 1] = '\0';
	} while ((namespace = strtok_r(NULL, ",", &saveptr)) != NULL);

	/*
	 * The ordering in which we join namespaces is important. We should
	 * always join the user namespace *first*. This is all guaranteed
	 * from the container_linux.go side of this, so we're just going to
	 * follow the order given to us.
	 */

	for (i = 0; i < num; i++) {
		struct namespace_t ns = namespaces[i];

		if (setns(ns.fd, ns.ns) < 0)
			bail("failed to setns to %s", ns.path);

		close(ns.fd);
	}

	free(namespaces);
}

/* Defined in cloned_binary.c. */
extern int ensure_cloned_binary(void);

void nsexec(void)
{
	/*
	 * We need to re-exec if we are not in a cloned binary. This is necessary
	 * to ensure that containers won't be able to access the host binary
	 * through /proc/self/exe. See CVE-2019-5736.
	 */
	if (ensure_cloned_binary() < 0)
		bail("could not ensure we are a cloned binary");

}

int main()
{
        printf( "before nsexec pid %d \n", getpid() );
	nsexec();
        printf( "after nsexec pid %d \n", getpid() );
	return 0;
}

#ifndef CLONE_H
#define CLONE_H
/*
 *  Copyright (C) 2007 IBM Corporation
 *
 *  Author: Cedric Le Goater <clg@fr.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 *
 */
#ifndef _GNU_SOURCE
#	define _GNU_SOURCE
#endif
#include <sched.h>

/* All of these are taken from include/uapi/linux/sched.h */
#ifndef CLONE_NEWNS
#	define CLONE_NEWNS 0x00020000 /* New mount namespace group */
#endif
#ifndef CLONE_NEWCGROUP
#	define CLONE_NEWCGROUP 0x02000000 /* New cgroup namespace */
#endif
#ifndef CLONE_NEWUTS
#	define CLONE_NEWUTS 0x04000000 /* New utsname namespace */
#endif
#ifndef CLONE_NEWIPC
#	define CLONE_NEWIPC 0x08000000 /* New ipc namespace */
#endif
#ifndef CLONE_NEWUSER
#	define CLONE_NEWUSER 0x10000000 /* New user namespace */
#endif
#ifndef CLONE_NEWPID
#	define CLONE_NEWPID 0x20000000 /* New pid namespace */
#endif
#ifndef CLONE_NEWNET
#	define CLONE_NEWNET 0x40000000 /* New network namespace */
#endif

#endif /* CLONE_H */

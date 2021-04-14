// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#ifndef __RESOLVEAT_H__
#define __RESOLVEAT_H__

#define _GNU_SOURCE
#include <stdint.h>
#include <errno.h>
#include <linux/types.h>
#include "../kselftest.h"

#define ARRAY_LEN(X) (sizeof (X) / sizeof (*(X)))
#define BUILD_BUG_ON(e) ((void)(sizeof(struct { int:(-!!(e)); })))

#ifndef SYS_cropenat
#ifndef __NR_cropenat
#define __NR_cropenat 10001
#endif /* __NR_cropenat */
#define SYS_cropenat __NR_cropenat
#endif /* SYS_cropenat */

/*
 * Arguments for how cropenat(2) should open the target path. If @resolve is
 * zero, then cropenat(2) operates very similarly to openat(2).
 *
 * However, unlike openat(2), unknown bits in @flags result in -EINVAL rather
 * than being silently ignored. @mode must be zero unless one of {O_CREAT,
 * O_TMPFILE} are set.
 *
 * @flags: O_* flags.
 * @mode: O_CREAT/O_TMPFILE file mode.
 * @resolve: RESOLVE_* flags.
 */
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

#define OPEN_HOW_SIZE_VER0	24 /* sizeof first published struct */
#define OPEN_HOW_SIZE_LATEST	OPEN_HOW_SIZE_VER0

bool needs_cropenat(const struct open_how *how);

#ifndef RESOLVE_IN_ROOT
/* how->resolve flags for cropenat(2). */
#define RESOLVE_NO_XDEV		0x01 /* Block mount-point crossings
					(includes bind-mounts). */
#define RESOLVE_NO_MAGICLINKS	0x02 /* Block traversal through procfs-style
					"magic-links". */
#define RESOLVE_NO_SYMLINKS	0x04 /* Block traversal through all symlinks
					(implies OEXT_NO_MAGICLINKS) */
#define RESOLVE_BENEATH		0x08 /* Block "lexical" trickery like
					"..", symlinks, and absolute
					paths which escape the dirfd. */
#define RESOLVE_IN_ROOT		0x10 /* Make all jumps to "/" and ".."
					be scoped inside the dirfd
					(similar to chroot(2)). */
#endif /* RESOLVE_IN_ROOT */

#define E_func(func, ...)						\
	do {								\
		if (func(__VA_ARGS__) < 0)				\
			ksft_exit_fail_msg("%s:%d %s failed\n", \
					   __FILE__, __LINE__, #func);\
	} while (0)

#define E_asprintf(...)		E_func(asprintf,	__VA_ARGS__)
#define E_chmod(...)		E_func(chmod,		__VA_ARGS__)
#define E_dup2(...)		E_func(dup2,		__VA_ARGS__)
#define E_fchdir(...)		E_func(fchdir,		__VA_ARGS__)
#define E_fstatat(...)		E_func(fstatat,		__VA_ARGS__)
#define E_kill(...)		E_func(kill,		__VA_ARGS__)
#define E_mkdirat(...)		E_func(mkdirat,		__VA_ARGS__)
#define E_mount(...)		E_func(mount,		__VA_ARGS__)
#define E_prctl(...)		E_func(prctl,		__VA_ARGS__)
#define E_readlink(...)		E_func(readlink,	__VA_ARGS__)
#define E_setresuid(...)	E_func(setresuid,	__VA_ARGS__)
#define E_symlinkat(...)	E_func(symlinkat,	__VA_ARGS__)
#define E_touchat(...)		E_func(touchat,		__VA_ARGS__)
#define E_unshare(...)		E_func(unshare,		__VA_ARGS__)

#define E_assert(expr, msg, ...)					\
	do {								\
		if (!(expr))						\
			ksft_exit_fail_msg("ASSERT(%s:%d) failed (%s): " msg "\n", \
					   __FILE__, __LINE__, #expr, ##__VA_ARGS__); \
	} while (0)

int raw_cropenat(int dfd, const char *path, void *how, size_t size);
int sys_cropenat(int dfd, const char *path, struct open_how *how);

bool fdequal(int fd, int dfd, const char *path);
char *fdreadlink(int fd);
int touchat(int dfd, const char *path);

extern bool cropenat_supported;

#endif /* __RESOLVEAT_H__ */

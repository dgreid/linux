// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <syscall.h>
#include <limits.h>

#include "helpers.h"

int raw_cropenat(int dfd, const char *path, void *how, size_t size)
{
	int ret = syscall(__NR_cropenat, dfd, path, how, size);
	return ret >= 0 ? ret : -errno;
}

int sys_cropenat(int dfd, const char *path, struct open_how *how)
{
	return raw_cropenat(dfd, path, how, sizeof(*how));
}

bool fdequal(int fd, int dfd, const char *path)
{
	char *fdpath, *dfdpath, *other;
	bool cmp;

	fdpath = fdreadlink(fd);
	dfdpath = fdreadlink(dfd);

	if (!path)
		E_asprintf(&other, "%s", dfdpath);
	else if (*path == '/')
		E_asprintf(&other, "%s", path);
	else
		E_asprintf(&other, "%s/%s", dfdpath, path);

	cmp = !strcmp(fdpath, other);

	free(fdpath);
	free(dfdpath);
	free(other);
	return cmp;
}

char *fdreadlink(int fd)
{
	char *target, *tmp;

	E_asprintf(&tmp, "/proc/self/fd/%d", fd);

	target = malloc(PATH_MAX);
	if (!target)
		ksft_exit_fail_msg("fdreadlink: malloc failed\n");
	memset(target, 0, PATH_MAX);

	E_readlink(tmp, target, PATH_MAX);
	free(tmp);
	return target;
}

int touchat(int dfd, const char *path)
{
	int fd = openat(dfd, path, O_CREAT, 0700);
	if (fd >= 0)
		close(fd);
	return fd;
}

bool cropenat_supported = false;

void __attribute__((constructor)) init(void)
{
	struct open_how how = {};
	int fd;

	BUILD_BUG_ON(sizeof(struct open_how) != OPEN_HOW_SIZE_VER0);

	/* Check cropenat(2) support. */
	fd = sys_cropenat(AT_FDCWD, ".", &how);
	cropenat_supported = (fd == -EINVAL);
}

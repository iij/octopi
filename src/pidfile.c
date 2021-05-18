/*
 *  pidfile.c
 *
 *  copyright (c) 2021 HANATAKA Shinya
 *  copyright (c) 2021 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pidfile.h"
#include "logging.h"
#include "ioutil.h"

static int fd = -1;
static char *filename = NULL;

void
open_pidfile(char *path)
{
	struct flock lock;

	/*
	 *  check file name
	 */
	if (path == NULL || path[0] != '/') {
		error_exit("pidfile must be absolute path.");
	}

	/*
	 *  check already opened
	 */
	if (fd != -1) {
		/* success */
		return;
	}

	/*
	 *  open pid file
	 */
	fd = open(path, O_WRONLY | O_CREAT, 0644);
	if (fd == -1) {
		error_exit("pidfile: open failed: %s: %s",
			   path ,strerror(errno));
	}

	/*
	 *  backup filename
	 */
	filename = strdup(path);
	if (filename == NULL)
		crit_exit("out of memory ... aborted");

	/*
	 *  lock pid file
	 */
        memset(&lock, 0, sizeof(struct flock));
	lock.l_type   = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start  = 0;
	lock.l_len    = 0;
	if (fcntl(fd, F_SETLK, &lock)) {
		if (errno == EACCES || errno == EAGAIN) {
			error_exit("another process use pidfile: %s", path);
		} else {
			error_exit("pidfile: open failed: %s: %s",
				   path ,strerror(errno));
		}
	}

	/*
	 *  truncate pid file
	 */
	if (ftruncate(fd, 0) != 0) {
		error_exit("pidfile: truncate failed: %s: %s",
			   path ,strerror(errno));
	}

	/*
	 *  remove pid file when normal process termination
	 */
	if (atexit(delete_pidfile)) {
		error_exit("pidfile: atexit failed: %s", strerror(errno));
	}
}

void
set_pidfile()
{
	char buf[32];
	int len;
	int wrote;

	/*
	 *  check opened
	 */
	if (fd == -1)
		return;

	/*
	 *  make pid data
	 */
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%u", getpid());
	len = strlen(buf);

	/*
	 *  truncate pid file
	 */
	if (ftruncate(fd, 0) != 0) {
		error_exit("pidfile: truncate failed: %s: %s",
			   filename, strerror(errno));
	}

	/*
	 *  write pid fata
	 */
	wrote = xwrite(fd, buf, len);
	if (wrote != len) {
		error_exit("pidfile: write failed: %s: %s",
			   filename, strerror(errno));		
	}
}

void
delete_pidfile()
{
	if (filename != NULL) {
		(void) unlink(filename);
		filename = NULL;
	}
	if (fd != -1) {
		(void) close(fd);
	}
}

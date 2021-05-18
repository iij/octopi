/*
 *  io_sync.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "octopi.h"
#include "logging.h"
#include "io_sync.h"

static ssize_t
sync_recv(OD *od, int fd, void *buf, size_t count)
{
	size_t red = 0;
	ssize_t n = 0;

	while(od->terminate == 0 && red < count) {
		n = read(fd, (char *)buf + red, count - red);

		if (n == -1) {
			if (errno == EINTR
			    || errno == EAGAIN
			    || errno == EWOULDBLOCK)
				continue;
			else
				return -1;
		} else if (n == 0) {
			return red;
		} else {
			red += n;
		}
	}

	return red;
}

static ssize_t
sync_send(OD *od, int fd, const void *buf, size_t count)
{
        size_t wrote = 0;
	ssize_t n = 0;

	while(od->terminate == 0 && wrote < count) {
		n = write(fd, (const char *)buf + wrote, count - wrote);
		if (n == -1) {
			if (errno == EINTR
			    || errno == EAGAIN
			    || errno == EWOULDBLOCK)
				continue;
			else
				return -1;
		} else if (n == 0) {
			return wrote;
		} else {
			wrote += n;
		}
	}

	return wrote;
}

void
put_greeting(OD *od, int fd, char *peer)
{
	int ret = sync_send(od, fd, SYNC_WELCOME, SYNC_CMD_SIZE);
	debug("sync from %s: send WELCOME", peer);

	if (ret < 0) {
		error_exit("sync from %s: send greeting failed: %s",
			   peer, strerror(errno));
	} else if (ret != SYNC_CMD_SIZE) {
		info("sync from %s: send greeting: aborted by peer", peer);
		exit(EXIT_SUCCESS);
	}
}

int
get_greeting(OD *od, int fd, char *peer)
{
	int ret;
	char buf[SYNC_CMD_SIZE];

	/*
	 *  recv greeting
	 */
	ret = sync_recv(od, fd, buf, SYNC_CMD_SIZE);
	if (ret < 0) {
		error("sync to %s: recv greeting failed: %s",
		      peer, strerror(errno));
		return FALSE;
	} else if (ret != SYNC_CMD_SIZE) {
		error("sync to %s: recv greeting: aborted by peer", peer);
		return FALSE;
	}

	/*
	 *  check greeting
	 */
	if (memcmp(SYNC_WELCOME, buf, SYNC_CMD_SIZE) != 0) {
		error("sync to %s: recv invalid greeting", peer);
		return FALSE;
	}

	debug("sync to %s: recv WELCOME", peer);
	return TRUE;
}

int
put_command(OD *od, int fd, int all, char *peer)
{
	int ret;

	/*
	 *  put command
	 */
	if (all) {
		ret = sync_send(od, fd, SYNC_REPLACE, SYNC_CMD_SIZE);
		debug("sync to %s: send REPLACE", peer);
	} else {
		ret = sync_send(od, fd, SYNC_INCLUDE, SYNC_CMD_SIZE);
		debug("sync to %s: send INCLUDE", peer);
	}
	if (ret < 0) {
		error("send to %s: send command failed: %s",
		      peer, strerror(errno));
		return FALSE;
	} else if (ret != SYNC_CMD_SIZE) {
		error("send to %s: send command: aboted by peer", peer);
		return FALSE;
	}

	return TRUE;
}

int
get_command(OD *od, int fd, char *peer)
{
	char buf[SYNC_CMD_SIZE];
	int replace;
	int ret;

	/*
	 *  recv command
	 */
	ret = sync_recv(od, fd, buf, SYNC_CMD_SIZE);
	if (ret < 0) {
		error_exit("sync from %s: recv command failed%s",
			   peer, strerror(errno));
	} else if (ret != SYNC_CMD_SIZE) {
		info("sync from %s: recv comamnd: aborted by peer", peer);
		exit(EXIT_SUCCESS);
	}

	/*
	 *  check command
	 */
	if (memcmp(SYNC_INCLUDE, buf, SYNC_CMD_SIZE) == 0) {
		debug("sync from %s: recv INCLUDE command", peer);
		replace = FALSE;
	} else if (memcmp(SYNC_REPLACE, buf, SYNC_CMD_SIZE) == 0) {
		debug("sync from %s: recv REPLACE command", peer);
		replace = TRUE;
	} else {
		info("sync from %s: recv unknown command: aborted", peer);
		sync_send(od, fd, SYNC_FAILURE, SYNC_CMD_SIZE);
		exit(EXIT_SUCCESS);
	}

	return replace;
}

void
put_waiting(OD *od, int fd, char *peer)
{
	int ret = sync_send(od, fd, SYNC_WAITING, SYNC_CMD_SIZE);
	debug("sync from %s: send WAITING", peer);

	if (ret < 0) {
		error_exit("sync from %s: send waiting failed %s",
			   peer, strerror(errno));
	} else if (ret != SYNC_CMD_SIZE) {
		info("sync from %s: send waiting: aboted by peer", peer);
		exit(EXIT_SUCCESS);
	}
}

int
get_waiting(OD *od, int fd, char *peer)
{
	char buf[SYNC_CMD_SIZE];
	int ret;

	/*
	 *  recv waiting response
	 */
	ret = sync_recv(od, fd, buf, SYNC_CMD_SIZE);
	if (ret < 0) {
		error("sync to %s: recv waiting: %s", peer, strerror(errno));
		return FALSE;
	} else if (ret != SYNC_CMD_SIZE) {
		error("sync to %s: recv waiting: aborted by peer", peer);
		return FALSE;
	}

	/*
	 *  check response
	 */
	if (memcmp(SYNC_WAITING, buf, SYNC_CMD_SIZE) != 0) {
		error("sync to %s: recv invalid waiting", peer);
		return FALSE;
	}

	debug("sync to %s: recv WAITING", peer);
	return TRUE;
}

void
put_success_result(OD *od, int fd, char *peer)
{
	int ret = sync_send(od, fd, SYNC_SUCCESS, SYNC_CMD_SIZE);
	debug("sync from %s: send SUCCESS", peer);

	if (ret < 0) {
		error_exit("sync from %s: send result of success failed %s",
			   peer, strerror(errno));
	} else if (ret != SYNC_CMD_SIZE) {
		info("sync from %s: send result of success: aboted by peer",
		     peer);
		exit(EXIT_SUCCESS);
	}
}

void
put_failure_result(OD *od, int fd, char *peer)
{
	int ret = sync_send(od, fd, SYNC_FAILURE, SYNC_CMD_SIZE);
	debug("sync from %s: send FAILURE", peer);

	if (ret < 0) {
		error_exit("sync from %s: send result of failure failed %s",
			   peer, strerror(errno));
	} else if (ret != SYNC_CMD_SIZE) {
		info("sync from %s: send result of failure: aboted by peer",
		     peer);
		exit(EXIT_SUCCESS);
	}
}

int
get_result(OD *od, int fd, char *peer)
{
	int ret;
	char buf[SYNC_CMD_SIZE];

	/*
	 *  recv result
	 */
	ret = sync_recv(od, fd, buf, SYNC_CMD_SIZE);
	if (ret < 0) {
		error("sync to %s: recv result failed: %s",
		      peer, strerror(errno));
		return FALSE;
	} else if (ret != SYNC_CMD_SIZE) {
		error("sync to %s: recv result: aborted by peer", peer);
		return FALSE;
	}

	/*
	 *  check result
	 */
	if (memcmp(SYNC_FAILURE, buf, SYNC_CMD_SIZE) == 0) {
		debug("sync to %s: recv FAILURE", peer);
		info("sync to %s: Failed", peer);
		return FALSE;
	} else if (memcmp(SYNC_SUCCESS, buf, SYNC_CMD_SIZE) != 0) {
		error("sync to %s: recv unknown result", peer);
		return FALSE;
	}

	debug("sync to %s: recv SUCCESS", peer);
	return TRUE;
}

/*
 *  ioutil.c
 *
 *  copyright (c) 2010-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/time.h>

#include "ioutil.h"

/*
 *  io timeout
 */
static int
check_timeout(struct timeval *x, struct timeval *s)
{
	struct timeval now;
	struct timeval *n = &now;

	/*
	 *  check disable timeout
	 */
	if (x->tv_sec == 0 && x->tv_usec == 0)
		return IO_OK;

	/*
	 *  add start
	 */
	x->tv_sec += s->tv_sec;
	x->tv_usec += s->tv_usec;
	if (x->tv_usec > 1000000L) {
		x->tv_sec ++;
		x->tv_usec -= 1000000L;
	}

	/*
	 *  subtract now
	 */
	gettimeofday(n, NULL);
	if (x->tv_sec > n->tv_sec) {
		x->tv_sec -= n->tv_sec;
	} else {
		x->tv_sec = 0;
		x->tv_usec = 0;
		return IO_FAIL;
	}
	if (x->tv_usec > n->tv_usec) {
		x->tv_usec -= n->tv_usec;
	} else if (x->tv_sec > 0) {
		x->tv_sec --;
		x->tv_usec += 1000000L - n->tv_usec;
	} else {
		x->tv_sec = 0;
		x->tv_usec = 0;
		return IO_FAIL;
	}

	if (x->tv_sec == 0 && x->tv_usec == 0)
		return IO_FAIL;

	return IO_OK;
}

/*
 *  wait file readable with timeout
 */
int
wait_readable(int fd, uint32_t timeout)
{
	struct timeval start;
	struct timeval left;
	int ret = IO_OK;
	int n = 0;

	/*
	 *  get start time
	 */
	gettimeofday(&start, NULL);

	/*
	 *  wait readable
	 */
	while (n <= 0) {
		fd_set rfds;

		/*
		 *  fd set
		 */
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		/*
		 *  calculate timeout
		 */
		left.tv_sec  = timeout / 1000;
		left.tv_usec = timeout % 1000;
		if (check_timeout(&left, &start) != IO_OK) {
			errno = ETIMEDOUT;
			ret = IO_FAIL;
			break;
		}

		/*
		 *  select fd
		 */
		n = select(fd + 1, &rfds, NULL, NULL, &left);
		if (n < 0) {
			if (errno == EINTR
			    || errno == EAGAIN
			    || errno == EWOULDBLOCK) {
				ret = IO_IRUPT;
			} else {
				ret = IO_FAIL;
			}
			break;
		}
	}

	return ret;
}

/*
 *  wait file writable with timeout
 */
int
wait_writable(int fd, uint32_t timeout)
{
	struct timeval start;
	struct timeval left;
	int ret = IO_OK;
	int n = 0;

	/*
	 *  get start time
	 */
	gettimeofday(&start, NULL);

	/*
	 *  wait readable
	 */
	while (n <= 0) {
		fd_set wfds;

		/*
		 *  fd set
		 */
		FD_ZERO(&wfds);
		FD_SET(fd, &wfds);

		/*
		 *  calculate timeout
		 */
		left.tv_sec  = timeout / 1000;
		left.tv_usec = timeout % 1000;
		if (check_timeout(&left, &start) != IO_OK) {
			errno = ETIMEDOUT;
			ret = IO_FAIL;
			break;
		}

		/*
		 *  select fd
		 */
		n = select(fd + 1, NULL, &wfds, NULL, &left);
		if (n < 0) {
			if (errno == EINTR
			    || errno == EAGAIN
			    || errno == EWOULDBLOCK) {
				ret = IO_IRUPT;
			} else {
				ret = IO_FAIL;
			}
			break;
		}
	}

	return ret;
}

/*
 *  read with interrupt check
 */
ssize_t
xread(int fd, void *buf, size_t count)
{
	size_t red = 0;
	ssize_t n = 0;

	while(red < count) {
		n = read(fd, (char *)buf + red, count - red);

		if (n == -1) {
			if (errno == EAGAIN
			    || errno == EINTR
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

/*
 *  write with interrupt check
 */
ssize_t
xwrite(int fd, const void *buf, size_t count)
{
	size_t wrote = 0;
	ssize_t n = 0;

	while(wrote < count) {
		n = write(fd, (const char *)buf + wrote, count - wrote);
		if (n == -1) {
			if (errno == EAGAIN
			    || errno == EINTR
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

/*
 *  fgets with interrupt check
 */
ssize_t
xgets(char *buf, int size, FILE *fp)
{
	if (size <= 0 || buf == NULL)
		return 0;

	while(fgets(buf, size, fp) == NULL) {
		if (feof(fp)) {
			buf[0] = '\0';
			return 0;
		} else if (errno != EINTR
			   && errno != EAGAIN
			   && errno != EWOULDBLOCK) {
			buf[0] = '\0';
			return -1;
		}
	}

	return strlen(buf);
}

/*
 *  sprintf for concatenate
 */
int
xprintf(char *buf, size_t *offset, size_t size, const char *format, ...)
{
	va_list ap;
	int len;

	va_start(ap, format);
	len = vsnprintf(buf + *offset, size - *offset, format, ap);
	va_end(ap);

	if (len >= size - *offset) {
		*offset = size - 1;
		return -1;
	}

	*offset += len;
	return 0;
}

/*
 *  io_buffer.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/select.h>

#include "ioutil.h"
#include "io_buffer.h"

IOBUF *
init_iobuf(uint32_t init, uint32_t min)
{
	IOBUF *buf = malloc(sizeof(IOBUF));

	/*
	 *  allocate I/O buffer
	 */
	if (buf == NULL)
		return NULL;
	memset((void*) buf, 0, sizeof(IOBUF));

	/*
	 *  initialize
	 */
	buf->fd    = STDOUT_FILENO;
	buf->size  = init;
	buf->min   = min;
	buf->eof   = 0;

	/*
	 *  allocate data buffer
	 */
	if (buf->size > 0) {
		buf->data = malloc(buf->size + 1);
		if (buf->data == NULL) {
			free(buf);
			return NULL;
		}
	}
	buf->begin = buf->data;
	buf->end   = buf->data;
	buf->next  = buf->data;

	return buf;
}

void
free_iobuf(IOBUF *buf)
{
	if (buf->data)
		free(buf->data);
	free(buf);
}

void
set_fd_iobuf(IOBUF *buf, int fd)
{
	buf->fd = fd;
}

static int
check_terminate(IOBUF *buf, char *end)
{
	uint8_t *nl;
	uint8_t token[TOKEN_SIZE + 1];
	int ret = IO_OK;

	while((nl = memchr(buf->next, '\n', buf->end - buf->next))) {
		uint8_t *line = buf->next;
		uint8_t *p;
		int i;

		/*
		 *  set next
		 */
		buf->next = nl + 1;

		/*
		 *  skip heading spaces
		 */
		for (p = line; strchr(" \t\r\f", *p); ++ p)
			;

		/*
		 *  get token
		 */
		for (i = 0; i < TOKEN_SIZE; ++ i) {
			if (strchr(" \n\t\r\f", *p)) {
				break;
			}
			token[i] = *p ++;
		}
		token[i] = 0;

		/*
		 *  check end
		 */
		if (strcasecmp((char*)token, end) == 0) {
			ret = IO_EOF;
			buf->eof = 1;
			break;
		}
	}

	return ret;
}

static int
enlarge_buf(IOBUF *buf)
{
	uint32_t size = buf->size;
	uint32_t used = buf->end - buf->data;
	uint8_t *data;

	/*
	 *  check non buffer mode
	 */
	if (buf->size == 0 || buf->data == NULL)
		return IO_OK;

	/*
	 *  check enough size
	 */
	if (used + buf->min <= size)
		return IO_OK;

	/*
	 *  calc new size
	 */
	while (used + buf->min > size)
		size *= 2;

	/*
	 *  enlarge data
	 */
	data = realloc(buf->data, size + 1);
	if (data == NULL)
		return IO_FAIL;

	/*
	 *  update
	 */
	buf->begin += data - buf->data;
	buf->end   += data - buf->data;
	buf->next  += data - buf->data;
	buf->size = size;
	buf->data = data;

	return IO_OK;
}

int
fill_iobuf(IOBUF *buf, uint32_t timeout, char *end)
{
	int ret = IO_OK;
	ssize_t n;

	/*
	 *  check non buffer mode
	 */
	if (buf->size == 0 || buf->data == NULL) {
		errno = ENOBUFS;
		return IO_FAIL;
	}

	while ((ret = check_terminate(buf, end)) == IO_OK) {
		/*
		 *  check end of file
		 */
		if (buf->eof)
			return IO_EOF;

		/*
		 *  wait readable
		 */
		ret = wait_readable(buf->fd, timeout);
		if (ret != IO_OK)
			break;

		/*
		 *  enlarge buffer
		 */
		ret = enlarge_buf(buf);
		if (ret != IO_OK)
			break;

		/*
		 *  read data
		 */
		n = read(buf->fd, buf->end, buf->size + buf->data - buf->end);
		if (n == 0) {
			ret = IO_EOF;
			buf->eof = 1;
			break;
		} else if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				ret = IO_IRUPT;
			} else {
				ret = IO_FAIL;
			}
			break;
		}
		buf->end += n;
	}

	return ret;
}

int
flush_iobuf(IOBUF *buf, uint32_t timeout)
{
	int ret = IO_OK;
	ssize_t n;

	/*
	 *  check non buffer mode
	 */
	if (buf->size == 0 || buf->data == NULL) {
		errno = EINVAL;
		return IO_FAIL;
	}

	while (buf->begin < buf->end) {
		/*
		 *  wait writable
		 */
		ret = wait_writable(buf->fd, timeout);
		if (ret != IO_OK)
			break;

		/*
		 *  write data
		 */
		n = write(buf->fd, buf->begin, buf->end - buf->begin);
		if (n <= 0) {
			if (errno == EINTR || errno == EAGAIN) {
				ret = IO_IRUPT;
			} else {
				ret = IO_FAIL;
			}
			break;
		}
		buf->begin += n;
	}

	return ret;
}

uint8_t *
read_iobuf(IOBUF *buf)
{
	uint8_t *nl;
	uint8_t *line;

	/*
	 *  check non buffer mode
	 */
	if (buf->size == 0 || buf->data == NULL)
		return NULL;

	/*
	 *  search NEWLINE
	 */
	nl = memchr(buf->begin, '\n', buf->next - buf->begin);
	if (nl) {
		uint8_t *p;

		line = buf->begin;
		buf->begin = nl + 1;
		for (p = line; p < nl; ++ p) {
			if (*p == 0 || strchr("\t\r\f", *p)) {
				*p = ' ';
			}
		}
		*nl = '\0';
	} else {
		line = NULL;
	}

	return line;
}

int
vzprintf(IOBUF *buf, char *format, va_list ap)
{
	int ret;

	/*
	 *  check undefined
	 */
	if (buf == NULL)
		return vdprintf(STDOUT_FILENO, format, ap);

	/*
	 *  check non buffer mode
	 */
	if (buf->size == 0 || buf->data == NULL)
		return vdprintf(buf->fd, format, ap);

	/*
	 *  enlarge buffer
	 */
	ret = enlarge_buf(buf);
	if (ret != IO_OK)
		return -1;

	/*
	 *  format message
	 */
	ret = vsnprintf((char*)buf->end, buf->min, format, ap);
	if (ret < 0) {
		return ret;
	} else if (ret >= buf->min) {
		errno = ENOBUFS;
		return -1;
	}

	/*
	 *  set size
	 */
	buf->end += ret;

	return ret;
}

int
zprintf(IOBUF *buf, char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vzprintf(buf, format, ap);
	va_end(ap);

	return ret;
}

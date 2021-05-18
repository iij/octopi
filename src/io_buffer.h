/*
 *  io_buffer.h
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */

#pragma once
#ifndef _IO_BUFFER_H
#define _IO_BUFFER_H

#include <stdint.h>

#define TOKEN_SIZE      (16)

typedef struct iobuffer {
	int      fd;
	uint32_t size;
	uint32_t min;
	uint8_t  *data;
	uint8_t  *begin;
	uint8_t  *end;
	uint8_t  *next;
	int      eof;
} IOBUF;

IOBUF *init_iobuf(uint32_t, uint32_t);
void free_iobuf(IOBUF *);
void set_fd_iobuf(IOBUF *, int);
int fill_iobuf(IOBUF *, uint32_t, char *end);
int flush_iobuf(IOBUF *, uint32_t);
uint8_t *read_iobuf(IOBUF *);
int zprintf(IOBUF *, char *, ...) __attribute__((format(printf, 2, 3)));

#endif /* _IO_BUFFER_H */

/*
 *  ioutil.h
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _IOUTIL_H
#define _IOUTIL_H

#include <stdio.h>

enum {
	IO_OK       = 1,
	IO_EOF      = 0,
	IO_FAIL     = -1,
	IO_IRUPT    = -2,
};

int wait_readable(int, uint32_t);
int wait_writable(int, uint32_t);
ssize_t xread(int, void*, size_t);
ssize_t xwrite(int, const void*, size_t);
ssize_t xgets(char*, int, FILE*);
int xprintf(char*, size_t *, size_t, const char *, ...)
	__attribute__((format(printf, 4, 5)));

#endif /* _IOUTIL_H */

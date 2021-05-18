/*
 *  logging.h
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _LOGGING_H
#define _LOGGING_H

#define LOG_MSG_LEN (256)

enum {
	LT_NONE   = 0,
	LT_DEBUG  = 1,
	LT_INFO   = 2,
	LT_NOTICE = 3,
	LT_WARN   = 4,
	LT_ERROR  = 5,
	LT_CRIT   = 6,
	LT_ALERT  = 7,
        LT_EMERG  = 8,
};

extern int logging_debug;

void logging(int level, char *format, ...)
	__attribute__((format(printf, 2, 3)));
void debug_on(void);
void debug_off(void);
void logging_init(char*, int);
void logging_start_syslog(void);
void logging_stop_syslog(void);
void logging_start_stderr(void);
void logging_stop_stderr(void);
void debug_packet(const char *header, const uint8_t *buf, const int);

#define debug(...) \
	do {if (logging_debug) {logging(LT_DEBUG, __VA_ARGS__);}} while (0)
#define info(...)    do {logging(LT_INFO,   __VA_ARGS__);} while (0)
#define notice(...)  do {logging(LT_NOTICE, __VA_ARGS__);} while (0)
#define warn(...)    do {logging(LT_WARN,   __VA_ARGS__);} while (0)
#define error(...)   do {logging(LT_ERROR,  __VA_ARGS__);} while (0)
#define crit(...)    do {logging(LT_CRIT,   __VA_ARGS__);} while (0)
#define alert(...)   do {logging(LT_ALERT,  __VA_ARGS__);} while (0)
#define emerge(...)  do {logging(LT_EMERGE, __VA_ARGS__);} while (0)
#define error_exit(...) \
	do {logging(LT_ERROR, __VA_ARGS__); exit(EXIT_FAILURE);} while (0)
#define alert_exit(...) \
	do {logging(LT_ALERT, __VA_ARGS__); exit(EXIT_FAILURE);} while (0)
#define crit_exit(...) \
	do {logging(LT_CRIT, __VA_ARGS__); exit(EXIT_FAILURE);} while (0)

#endif /* _LOGGING_H */

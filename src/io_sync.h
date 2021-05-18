/*
 *  io_sync.h
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _IO_SYNC_H
#define _IO_SYNC_H

#include "octopi.h"

#define SYNC_CMD_SIZE  (9)
#define SYNC_INCLUDE   "INCLUDE\r\n"
#define SYNC_REPLACE   "REPLACE\r\n"
#define SYNC_WELCOME   "WELCOME\r\n"
#define SYNC_WAITING   "WAITING\r\n"
#define SYNC_SUCCESS   "SUCCESS\r\n"
#define SYNC_FAILURE   "FAILURE\r\n"

void put_greeting(OD *, int, char *);
int  get_greeting(OD *, int, char *);
int  put_command(OD *, int, int, char *);
int  get_command(OD *, int, char *);
void put_waiting(OD *, int, char *);
int  get_waiting(OD *, int, char *);
void put_success_result(OD *, int, char *);
void put_failure_result(OD *, int, char *);
int  get_result(OD *, int, char *);

#endif /* _IO_SYNC_H */

/*
 *  pidfile.c
 *
 *  copyright (c) 2021 HANATAKA Shinya
 *  copyright (c) 2021 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _PIDFILE_H
#define _PIDFILE_H

void open_pidfile(char *);
void set_pidfile(void);
void delete_pidfile(void);

#endif /* _PIDFILE_H */

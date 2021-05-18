/*
 *  setproctitle.h
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _SETPROCTITLE_H
#define _SETPROCTITLE_H

void setproctitle_init(int, char**, char**);
void setproctitle(const char*);

#endif /* _SETPROCTITLE_H */

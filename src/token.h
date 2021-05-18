/*
 *  token.h
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _TOKEN_H
#define _TOKEN_H

#include <stdint.h>
#include "addrutil.h"

int str_to_uid(char*, uid_t*, uint32_t);
int str_to_gid(char*, gid_t*, uint32_t);
char* get_token(char**);
char* read_one_token(char*, int, char*, char**);
int read_debug(char*, int, char*, char**);
char* read_str(char*, int, char*, char**, uint32_t, uint32_t);
uint32_t read_num(char*, int, char*, char**, uint32_t, uint32_t);
int read_log_facility(char*, int, char*, char**);
uid_t read_user(char*, int, char*, char**, uint32_t);
gid_t read_group(char*, int, char*, char**, uint32_t);
ADDR *read_cidr(char*, int, char*, char**);
ADDR *read_addr(char*, int, char*, char**);

#endif /* _TOKEN_H */

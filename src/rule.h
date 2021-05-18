/*
 *  rule.h
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _RULE_H
#define _RULE_H

#include "octopi.h"
#include "addrutil.h"
#include "lpm.h"
#include "que.h"

typedef struct queue_relay {
	ADDR *relay;
} QRELAY;

/* kicker.c */
void start_talkers(OD *, MLIST *);

/* talker.c */
void talker(OD *, qpos_t);

/* rule_update.c */
int update_rules(OD*, int, uint8_t, int, char *);

/* rule_util.c */
int conv_vni(char*, uint32_t*, char**);
int conv_proto(char*, uint8_t*, char**);
int conv_target(char*, npos_t*, int, char**);
int conv_relay(npos_t, char *, int, char **);
int conv_relays(npos_t, int, char**, int, char**);
int conv_acl(npos_t, char *, int, char **);
int conv_que_update(char *, int *);

void open_rule_file(OD*, int);
void init_rule_file(OD*, uint32_t, uint32_t);
void close_rule_file(OD*);
void sync_rule_file(OD*);

void open_queue_file(OD*, int);
void init_queue_file(OD*, uint32_t, uint32_t);
void close_queue_file(OD*);

QRELAY *init_qrelay(OD *);
void get_qrelay(OD *, QRELAY *, vxid_t);
void push_qrelay(OD *, QRELAY *, vxid_t);
void pull_qrelay(OD *, QRELAY *, vxid_t);
void free_qrelay(OD *, QRELAY *);

#endif /* _RULE_H */

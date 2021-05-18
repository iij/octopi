/*
 *  command.h
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _COMMAND_H
#define _COMMAND_H
#include "octopi.h"
#include "lpm.h"
#include "que.h"

void command_init(OD*, int, char**);
void command_show(OD*, int, char**);
void command_list(OD*, int, char**);
void command_show(OD*, int, char**);
void command_find(OD*, int, char**);
void command_add(OD*, int, char**);
void command_delete(OD*, int, char**);
void command_move(OD*, int, char**);
void command_flush(OD*, int, char**);
void command_pause(OD*, int, char**);
void command_unpause(OD*, int, char**);
void command_save(OD*, int, char**);
void command_restore(OD*, int, char**);
void command_update(OD*, int, char**);
void command_sync(OD*, int, char**);
void command_fsck(OD*, int, char**);
void command_dump(OD*, int, char**);
void command_queue(OD*, int, char**);
void command_queue_list(OD*, int, char**);
void command_queue_show(OD*, int, char**);
void command_queue_init(OD*, int, char**);
void command_queue_add(OD*, int, char**);
void command_queue_delete(OD*, int, char**);
void command_queue_enable(OD*, int, char**);
void command_queue_disable(OD*, int, char**);
void command_queue_sync(OD*, int, char**);
void command_queue_dump(OD*, int, char**);
void command_node(OD*, int, char**);
void command_node_list(OD*, int, char**);
void command_node_add(OD*, int, char**);
void command_node_delete(OD*, int, char**);
void command_backup(OD*, int, char**);
void command_backup_list(OD*, int, char**);
void command_backup_add(OD*, int, char**);
void command_backup_delete(OD*, int, char**);
void command_acl(OD*, int, char**);
void command_acl_list(OD*, int, char**);
void command_acl_add(OD*, int, char**);
void command_acl_delete(OD*, int, char**);
void command_rule(OD*, int, char**);

#endif /* _COMMAND_H */

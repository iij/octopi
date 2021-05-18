/*
 *  queue.h  :  synchronize queue
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _QUE_H
#define _QUE_H

#include <stdint.h>

#include "addrutil.h"
#include "io_buffer.h"
#include "proto.h"

typedef uint32_t qpos_t;

typedef struct member_list {
	qpos_t *member;
	int    size;
	int    num;
	int    pos;
} MLIST;

enum {
	QUE_OK            = 0,
	QUE_FAIL          = 1,
};

enum {
	QUE_UPDATE_AUTO   = 0,
	QUE_UPDATE_RELAY  = 1,
	QUE_UPDATE_MEMBER = 2,
	QUE_UPDATE_BOTH   = 3,
};

/* open/close functions */
void QUE_lock();
void QUE_unlock();
void QUE_disk_sync();
void QUE_init(char *, uint32_t, uint32_t);
void QUE_open(char *, int);
void QUE_close();
void QUE_open_or_init(char *, int, uint32_t, uint32_t);
void QUE_reinit(char *, uint32_t, uint32_t);

/* node functions */
int QUE_node_add(ADDR *, ADDR *);
int QUE_node_delete(ADDR *, ADDR *);

/* backup functions */
int QUE_backup_add(ADDR *);
int QUE_backup_delete(ADDR *);

/* queue functions */
int QUE_queue_add(int, ADDR *, vxid_t);
int QUE_queue_add_all(vxid_t);
void QUE_queue_delete(int, ADDR *, vxid_t);
void QUE_queue_delete_all(vxid_t);

/* queue sync functions */
void QUE_member_addr(qpos_t, ADDR *);
uint32_t QUE_make_data(IOBUF *, qpos_t, int *, int *);
void QUE_sync_start(qpos_t);
void QUE_sync_finish(qpos_t, uint32_t);
void QUE_sync_abort(qpos_t);

/* queue list functions */
MLIST * QUE_init_mlist(int);
void QUE_free_mlist(MLIST *);
MLIST * QUE_get_sync_list(MLIST *, int, ADDR *);
MLIST * QUE_get_sync_list_all(MLIST *);

/* display functions */
void QUE_node_list(IOBUF *buf, char *, ADDR *);
void QUE_backup_list(IOBUF *buf, char *);
void QUE_queue_list(IOBUF *buf, ADDR *);
void QUE_queue_list_all(IOBUF *buf);
void QUE_queue_show(IOBUF *buf, ADDR *);
void QUE_queue_show_all(IOBUF *buf);

/* dump fanctions */
void QUE_dump_header(IOBUF *);
void QUE_count_node(IOBUF *);
void QUE_dump_all(IOBUF *);

#endif /* _QUE_H */

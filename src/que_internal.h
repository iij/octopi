/*
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _QUE_INTERNAL_H
#define _QUE_INTERNAL_H

#include "lpm.h"
#include "que.h"

#define OCTOPI_QUE_MAGIC    (0x4f43544f50495155UL)
#define OCTOPI_QUE_REVMAGIC (0x555149504f54434fUL)
#define OCTOPI_QUE_VERSION  (0x0000000100000003UL)
#define QUE_HEADER_SIZE     (256)
#define QUE_BUF_SIZE        (4096)
#define BACKUP_NODE         (0)

enum {
	QUE_TYPE_NONE     = 0,
	QUE_TYPE_RELAY    = 1,
	QUE_TYPE_BACKUP   = 2,
	QUE_TYPE_MEMBER   = 3,
	QUE_TYPE_QUEUE    = 4,
};

enum {
	QUE_MARK_NONE     = 0,
	QUE_MARK_UPDATE   = 1,
};

struct que_header {
	union {
		struct {
			uint64_t magic;
			uint64_t version;
			uint32_t node_size;
			uint32_t qpos_size;
			uint32_t header_size;
			uint32_t pool_size;
			uint32_t hash_size;
			uint32_t data_size;
			uint32_t file_size;
			qpos_t   pool_head;
			qpos_t   pool_tail;
		} __attribute__((__packed__));
		unsigned char buffer[QUE_HEADER_SIZE];
	};
};

struct que_data;
struct que_data {
	uint8_t  type;                        /*  1 byte  */
	uint8_t  proto;                       /*  1 byte  */
	uint8_t  mark;                        /*  1 byte  */
	uint8_t  action;                      /*  1 byte  */
	qpos_t   next;                        /*  4 bytes */
	qpos_t   link;                        /*  4 bytes */
        qpos_t   relay;                       /*  4 bytes */
	qpos_t   member;                      /*  4 bytes */
	qpos_t   queue;                       /*  4 bytes */
	uint32_t update;                      /*  4 bytes */
	uint32_t sync;                        /*  4 bytes */
	uint64_t update_time;                 /*  8 bytes */
	uint64_t insert_time;                 /*  8 bytes */
	union {                               /* 16 bytes */
		ip4_t     ipv4_addr;
		ip6_t     ipv6_addr;
		vxid_t    vni;
		uint8_t   addr[16];
		uint16_t  addr16[8];
		uint32_t  addr32[4];
		uint64_t  addr64[2];
	};
};

/* ------------------------------------ */

extern struct que_header *q_header;
extern struct que_data *q_pool;
extern qpos_t *q_hash;

#define TYPE(i)        (q_pool[(i)].type)
#define PROTO(i)       (q_pool[(i)].proto)
#define MARK(i)        (q_pool[(i)].mark)
#define ACTION(i)      (q_pool[(i)].action)
#define V4ADDR(i)      (q_pool[(i)].ipv4_addr)
#define V6ADDR(i)      (q_pool[(i)].ipv6_addr)
#define VNI(i)         (q_pool[(i)].vni)
#define NEXT(i)        (q_pool[(i)].next)
#define LINK(i)        (q_pool[(i)].link)
#define MEMBER(i)      (q_pool[(i)].member)
#define QUEUE(i)       (q_pool[(i)].queue)
#define UPDATE(i)      (q_pool[(i)].update)
#define SYNC(i)        (q_pool[(i)].sync)
#define RELAY(i)       (q_pool[(i)].relay)
#define UPDATE_TIME(i) (q_pool[(i)].update_time)
#define INSERT_TIME(i) (q_pool[(i)].insert_time)

/*
 *  marks functions
 */
static inline int
test_update(qpos_t n)
{
	return (MARK(n) & QUE_MARK_UPDATE);
}

static inline void
mark_update(qpos_t n)
{
	MARK(n) |= QUE_MARK_UPDATE;
}

static inline void
unmark_update(qpos_t n)
{
	MARK(n) &= ~QUE_MARK_UPDATE;
}

static inline void
put_node(qpos_t i)
{
	NEXT(i) = 0;
	if (q_header->pool_head == 0) {
		q_header->pool_head = i;
	} else {
		NEXT(q_header->pool_tail) = i;
	}
	q_header->pool_tail = i;
	MARK(i) = 0;
}

static inline qpos_t
get_node()
{
	qpos_t node = q_header->pool_head;

	if (node == 0)
		return 0;
	q_header->pool_head = NEXT(node);
	memset(q_pool + node, 0, sizeof(struct que_data));
	mark_update(node);

	return node;
}

static inline int
match_qaddr(qpos_t n, ADDR *a)
{
	if (PROTO(n) == PROTO_IP4 && a->af == AF_INET)
		if (V4ADDR(n) == a->ipv4_addr)
			return 1;
	if (PROTO(n) == PROTO_IP6 && a->af == AF_INET6)
		if (V4ADDR(n) == a->ipv6_addr)
			return 1;
	return 0;
}

/* utility functions */
uint32_t QUE_calc_addr_hash(ADDR *);
uint64_t QUE_now();
void QUE_delete_all_queue(qpos_t);
qpos_t QUE_find_relay(ADDR *);
qpos_t QUE_find_member(qpos_t, ADDR *);

#endif /* _QUE_INTERNAL_H */

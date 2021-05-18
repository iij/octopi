/*
 *  lpm_internal.h
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _LPM_INTERNAL_H
#define _LPM_INTERNAL_H

#include "lpm.h"

enum {
	LPM_TYPE_NONE     = 0,
	LPM_TYPE_ROOT     = 1,
	LPM_TYPE_NODE     = 2,
	LPM_TYPE_RELAY    = 3,
	LPM_TYPE_BASE     = 255,
};

enum {
	LPM_MARK_NONE     = 0,
	LPM_MARK_UPDATE   = 1,
	LPM_MARK_RELAY    = 2,
	LPM_MARK_RESTORE  = 4,
	LPM_MARK_USED     = 8,
};

#define mfence()   asm volatile ("mfence":::"memory")

#define OCTOPI_RULE_MAGIC    (0x4f43544f50494442UL)
#define OCTOPI_RULE_REVMAGIC (0x424449504f54434fUL)
#define OCTOPI_RULE_VERSION  (0x0000000100000003UL)
#define LPM_HEADER_SIZE (256)
#define DATA_BUF_SIZE (4096)

struct lpm_header {
	union {
		struct {
			uint64_t magic;
			uint64_t version;
			uint32_t node_size;
			uint32_t npos_size;
			uint32_t header_size;
			uint32_t pool_size;
			uint32_t hash_size;
			uint32_t data_size;
			uint32_t file_size;
			npos_t   pool_head;
			npos_t   pool_tail;
			uint8_t  pause;
			uint8_t  queue_sync;
		} __attribute__((__packed__));
		unsigned char buffer[LPM_HEADER_SIZE];
	};
};

struct lpm_data;
struct lpm_data {
	uint8_t type;                                /*  1 bytes */
	uint8_t proto;                               /*  1 bytes */
	uint8_t mask;                                /*  1 bytes */
	uint8_t forkbit;                             /*  1 bytes */
	uint32_t mark;                               /*  4 bytes */
	uint8_t reserved[24];                        /* 24 bytes */
	npos_t next;                                 /*  4 bytes */
	npos_t relay;                                /*  4 bytes */
	npos_t child[2];                             /*  8 bytes */
	union {                                      /* 16 bytes */
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

extern struct lpm_header *header;
extern struct lpm_data *pool;
extern npos_t *hash;

#define MARK(i)    (pool[(i)].mark)
#define NEXT(i)    (pool[(i)].next)
#define RELAY(i)   (pool[(i)].relay)
#define CHILD(i,n) (pool[(i)].child[(n)])
#define FORKBIT(i) (pool[(i)].forkbit)
#define VNI(i)     (pool[(i)].vni)
#define V4ADDR(i)  (pool[(i)].ipv4_addr)
#define V6ADDR(i)  (pool[(i)].ipv6_addr)
#define ADDR(i)    (pool[(i)].IP_ADDR)
#define MASK(i)    (pool[(i)].mask)
#define TYPE(i)    (pool[(i)].type)
#define PROTO(i)   (pool[(i)].proto)


/*
 *  calc hash position
 */
static inline uint32_t
calc_hash(vxid_t vni, uint8_t proto)
{
	if (proto == PROTO_IP6)
		vni += 123456;
	return vni % header->hash_size;
}

/*
 *  marks functions
 */
static inline int
test_update(npos_t n)
{
	return (MARK(n) & LPM_MARK_UPDATE);
}

static inline void
mark_update(npos_t n)
{
	if (!test_update(n))
		MARK(n) |= LPM_MARK_UPDATE;
}

static inline void
unmark_update(npos_t n)
{
	if (test_update(n))
		MARK(n) &= ~LPM_MARK_UPDATE;
}

static inline void
mark_update_tree(npos_t n)
{
	npos_t r;

	mark_update(n);
	for (r = RELAY(n); r; r = RELAY(r))
		mark_update(r);

	if (CHILD(n, 0))
		mark_update_tree(CHILD(n, 0));
	if (CHILD(n, 1))
		mark_update_tree(CHILD(n, 1));
}

static inline void
unmark_update_tree(npos_t n)
{
	npos_t r;

	if (CHILD(n, 0))
		unmark_update_tree(CHILD(n, 0));
	if (CHILD(n, 1))
		unmark_update_tree(CHILD(n, 1));

	for (r = RELAY(n); r; r = RELAY(r))
		unmark_update(r);
	unmark_update(n);
}

static inline int
test_relay(npos_t n)
{
	return (MARK(n) & LPM_MARK_RELAY);
}

static inline void
mark_relay(npos_t n)
{
	if (!test_relay(n))
		MARK(n) |= LPM_MARK_RELAY;
}

static inline void
unmark_relay(npos_t n)
{
	if (test_relay(n))
		MARK(n) &= ~LPM_MARK_RELAY;
}

static inline int
test_restore(npos_t n)
{
	return (MARK(n) & LPM_MARK_RESTORE);
}

static inline void
mark_restore(npos_t n)
{
	if (!test_restore(n))
		MARK(n) |= LPM_MARK_RESTORE;
}

static inline void
unmark_restore(npos_t n)
{
	if (test_restore(n))
		MARK(n) &= ~LPM_MARK_RESTORE;
}

static inline int
test_used(npos_t n)
{
	return (MARK(n) & LPM_MARK_USED);
}

static inline void
mark_used(npos_t n)
{
	if (!test_used(n))
		MARK(n) |= LPM_MARK_USED;
}

static inline void
unmark_used(npos_t n)
{
	if (test_used(n))
		MARK(n) &= ~LPM_MARK_USED;
}

static inline void
mark_used_tree(npos_t n)
{
	npos_t r;

	mark_used(n);
	for (r = RELAY(n); r; r = RELAY(r))
		mark_used(r);

	if (CHILD(n, 0))
		mark_used_tree(CHILD(n, 0));
	if (CHILD(n, 1))
		mark_used_tree(CHILD(n, 1));
}

static inline void
unmark_used_tree(npos_t n)
{
	npos_t r;

	if (CHILD(n, 0))
		unmark_used_tree(CHILD(n, 0));
	if (CHILD(n, 1))
		unmark_used_tree(CHILD(n, 1));

	for (r = RELAY(n); r; r = RELAY(r))
		unmark_used(r);
	unmark_used(n);
}

static inline void
unmark_all(npos_t n)
{
	if (MARK(n))
		MARK(n) = 0;
}

static inline void
unmark_all_tree(npos_t n)
{
	npos_t r;

	if (CHILD(n, 0))
		unmark_all_tree(CHILD(n, 0));
	if (CHILD(n, 1))
		unmark_all_tree(CHILD(n, 1));

	for (r = RELAY(n); r; r = RELAY(r))
		unmark_all(r);
	unmark_all(n);
}

/*
 *  node functions
 */
static inline npos_t
get_node()
{
	npos_t node = header->pool_head;

	if (node == 0)
		return 0;
	header->pool_head = NEXT(node);
	memset(pool + node, 0, sizeof(struct lpm_data));
	mark_update(node);

	return node;
}

static inline void
put_node(npos_t i)
{
	NEXT(i) = 0;
	if (header->pool_head == 0) {
		header->pool_head = i;
	} else {
		NEXT(header->pool_tail) = i;
	}
	header->pool_tail = i;
	MARK(i) = 0;
}

static inline void
release_node(npos_t node)
{
	npos_t r;

	mark_update(node);
	for (r = RELAY(node); r; r = RELAY(r))
		mark_update(r);
	for (r = RELAY(node); r; r = RELAY(r))
                put_node(r);
        put_node(node);
}

static inline void
release_tree(npos_t n)
{
	if (CHILD(n, 0))
		release_tree(CHILD(n, 0));
	if (CHILD(n, 1))
		release_tree(CHILD(n, 1));
	release_node(n);
}

/*
 *   atomic functions
 */
static inline void
atomic_set(npos_t p, int b, npos_t n)
{
	mfence();
	CHILD(p, b) = n;
	mfence();
	unmark_update(n);
}

static inline void
atomic_replace(npos_t p, int b, npos_t n)
{
	npos_t c = CHILD(p, b);

	if (c)
		mark_update(c);

	atomic_set(p, b, n);
	if (c)
		put_node(c);
}

#endif /* _LPM_INTERNAL_H */

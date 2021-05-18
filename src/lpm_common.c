/*
 *  lpm_common.c
 *
 *  common template function for IPv4 and IPv6
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <string.h>
#include "lpm.h"
#include "lpm_internal.h"

/*
 *  sub functions
 */
static inline int
check_addr(npos_t x, npos_t y)
{
	if (PROTO(x) == PROTO_IP4
	    && PROTO(y) == PROTO_IP4
	    && V4ADDR(x) == V4ADDR(y)) {
		return LPM_OK;
	}
	if (PROTO(x) == PROTO_IP6
	    && PROTO(y) == PROTO_IP6
	    && V6ADDR(x) == V6ADDR(y)) {
		return LPM_OK;
	}
	return LPM_FAIL;
}

static inline int
check_cidr(IP_t addr1, uint8_t mask1, IP_t addr2, uint8_t mask2)
{
	IP_t m;

	if (mask1 < mask2) {
		m = IPmask[mask1];
	} else {
		m = IPmask[mask2];
	}

	if ((addr1 & m) == (addr2 & m)) {
		return LPM_OK;
	}

	return LPM_FAIL;
}

static inline int
get_forkbit(IP_t addr, uint8_t forkbit)
{
	addr >>= (IPsize - forkbit);
	return addr & 1;
}

static inline void
setup_fork(npos_t f, npos_t c1, npos_t c2)
{
	if (c2 == 0) {
		CHILD(f, 0) = c1;
		CHILD(f, 1) = c2;
		FORKBIT(f) = 0;
		return;
	}
	if (c1 == 0) {
		CHILD(f, 0) = c2;
		CHILD(f, 1) = c1;
		FORKBIT(f) = 0;
		return;
	}

	if (ADDR(c1) < ADDR(c2)) {
		CHILD(f, 0) = c1;
		CHILD(f, 1) = c2;
	} else {
		CHILD(f, 0) = c2;
		CHILD(f, 1) = c1;
	}
	FORKBIT(f) = diff_addr(ADDR(c1), ADDR(c2));
}

static inline npos_t
new_fork(npos_t c1, npos_t c2)
{
	npos_t f = get_node();
	if (f == 0)
		return 0;

	TYPE(f) = LPM_TYPE_NODE;
	PROTO(f) = IP_PROTO;
	setup_fork(f, c1, c2);
	MASK(f) = FORKBIT(f) - 1;
	ADDR(f) = ADDR(c1) & IPmask[MASK(f)];

	return f;
}

static inline npos_t
new_node(IP_t addr, uint8_t mask, npos_t r)
{
	npos_t n = get_node();
	if (n == 0)
		return 0;

	TYPE(n) = LPM_TYPE_NODE;
	PROTO(n) = IP_PROTO;
	ADDR(n) = addr;
	MASK(n) = mask;
	RELAY(n) = r;

	return n;
}

/*
 *  relay functions
 */
static npos_t
shrink_relay(npos_t base, npos_t new)
{
	npos_t r = 0;
	npos_t t = 0;
	npos_t n = new;
	npos_t p;

	while(n) {
		int found = 0;
		for (p = RELAY(base); p; p = RELAY(p)) {
			if (check_addr(p, n) == LPM_OK) {
				found = 1;
				break;
			}
		}
		if (found == 0) {
			if (t == 0) {
				r = n;
				t = n;
			} else {
				RELAY(t) = n;
				t = n;
			}
			n = RELAY(n);
			RELAY(t) = 0;
		} else {
			npos_t b = n;
			n = RELAY(n);
			put_node(b);
		}
	}

	return r;
}

static int
add_broadcast(npos_t root, npos_t add)
{
	npos_t tail;
	npos_t r;
	npos_t n;
	int found;

	for (tail = root; RELAY(tail); tail = RELAY(tail))
		;

	for (n = RELAY(add); n; n = RELAY(n)) {
		found = 0;
		if (PROTO(n) == PROTO_IP4
		    && V4ADDR(n) == LPM_RELAY_Drop)
			continue;
		if (PROTO(n) == PROTO_IP4
		    && V4ADDR(n) == LPM_RELAY_Broadcast)
			continue;

		for (r = RELAY(root); r; r = RELAY(r)) {
			if (check_addr(r, n) == LPM_OK) {
				found = 1;
				break;
			}
		}
		if (found == 0) {
			npos_t new  = get_node();
			if (new == 0)
				return 0;

			TYPE(new)   = LPM_TYPE_RELAY;
			PROTO(new)  = PROTO(n);
			V6ADDR(new) = V6ADDR(n);
			MASK(new)   = MASK(n);
			mfence();
			RELAY(tail) = new;
			mfence();
			unmark_update(new);
			tail = new;
		}
	}

	return RELAY(add);
}

static void
walk_unmark_relay(npos_t root, npos_t n)
{
	npos_t r;
	npos_t s;

	for (r = RELAY(n); r; r = RELAY(r)) {
		for (s = RELAY(root); s; s = RELAY(s)) {
			if (test_relay(s) && check_addr(r, s) == LPM_OK) {
				unmark_relay(s);
			}
		}
	}

	if (CHILD(n, 0))
		walk_unmark_relay(root, CHILD(n, 0));
	if (CHILD(n, 1))
		walk_unmark_relay(root, CHILD(n, 1));
}


static void
del_broadcast(npos_t root)
{
	npos_t r;

	for (r = RELAY(root); r; r = RELAY(r))
		mark_relay(r);

	walk_unmark_relay(root, CHILD(root, 0));

	for (r = root; RELAY(r); r = RELAY(r)) {
		if (test_relay(RELAY(r))) {
			int rr = RELAY(r);

			mark_update(rr);
			mfence();
			RELAY(r) = RELAY(rr);
			mfence();
			unmark_relay(rr);
			put_node(rr);
		}
	}
}

static void
add_relay(npos_t t, npos_t n)
{
	npos_t r = shrink_relay(t, RELAY(n));
	npos_t tail;
	npos_t rr;

	if (r == 0) {
		put_node(n);
		return;
	}

	for (tail = t; RELAY(tail); tail = RELAY(tail))
		;

	mfence();
	RELAY(tail) = r;
	mfence();

	for (rr = r; rr; rr = RELAY(rr))
		unmark_update(rr);
	put_node(n);
}

static void
move_relay(npos_t t, npos_t n)
{
	npos_t orig = RELAY(t);
	npos_t r;

	for (r = orig; r; r = RELAY(r))
		mark_update(r);
	mfence();
	RELAY(t) = RELAY(n);
	mfence();
	for (r = RELAY(t); r; r = RELAY(r))
		unmark_update(r);

	for (r = orig; r; r = RELAY(r))
		put_node(r);
	put_node(n);
}


static int
del_relay(npos_t node, npos_t del)
{
	npos_t prev = node;
	npos_t t;
	npos_t d;

	if (RELAY(del) == 0)
		return LPM_FAIL;

	for (t = RELAY(node); t; t = RELAY(t)) {
		int found = 0;
		for (d = RELAY(del); d; d = RELAY(d)) {
			if (check_addr(t, d) == LPM_OK) {
				found = 1;
				break;
			}
		}
		if (found) {
			mark_update(t);
			mfence();
			RELAY(prev) = RELAY(t);
			mfence();
			put_node(t);
		} else {
			prev = t;
		}
	}
	if (RELAY(node))
		return LPM_OK;

	return LPM_FAIL;
}

/*
 *  wild-card vni
 */
static inline void
set_wild_card(vxid_t vni, npos_t root)
{
	if (vni == VNI_ANY)
		CHILD(0, IP_WILD_CARD) = root;
}

/*
 *  add rules
 */

/*
 *   -S           ->    -S-N
 *
 *   -S-c         ->    -M-c
 *                        `N
 */
static inline int
add_leaf(npos_t p, int b, npos_t t, npos_t n)
{
	npos_t r;

	if (CHILD(t, 0) == 0) {
		atomic_set(t, 0, n);
		return LPM_OK;
	}

	r = new_fork(CHILD(t, 0), n);
	if (r == 0)
		return LPM_FAIL;
	ADDR(r)  = ADDR(t);
	MASK(r)  = MASK(t);
	RELAY(r) = RELAY(t);

	atomic_replace(p, b, r);
	return LPM_OK;
}

/*
 *   -f-c         ->    -f-c
 *     `C                 `f-C
 *                          `N
 */
static inline int
add_fork(npos_t p, int b, npos_t t, npos_t n)
{
	npos_t f = new_fork(t, n);
	if (f == 0)
		return LPM_FAIL;

	atomic_set(p, b, f);
	return LPM_OK;
}

/*
 *   -S-c         ->    -S-N-c
 *
 *   -F-c         ->    -F-c
 *     `c                 `N-c
 */
static inline int
insert_node(npos_t t, int b, npos_t c, npos_t n)
{
	CHILD(n, 0) = c;
	atomic_set(t, b, n);
	return LPM_OK;
}

/*
 *
 *   -M-c         ->    -S-N-c
 *     `c                   `c
 */
static inline int
insert_mixed(npos_t p, int b, npos_t t, npos_t n)
{
	npos_t r;

	if (CHILD(t, 1) == 0) {
		CHILD(n, 0) = CHILD(t, 0);
		atomic_set(t, 0, n);
		return LPM_OK;
	}

	setup_fork(n, CHILD(t, 0), CHILD(t, 1));
	r = new_node(ADDR(t), MASK(t), RELAY(t));
	if (r == 0)
		return LPM_FAIL;
	CHILD(r, 0) = n;

	atomic_replace(p, b, r);
	return LPM_OK;
}

/*
 *   -F-c         ->    -M-c
 *     `c                 `c
 */
static inline int
update_node(npos_t p, int b, npos_t t, npos_t n)
{
	setup_fork(n, CHILD(t,0), CHILD(t, 1));

	atomic_replace(p, b, n);
	return LPM_OK;
}

/*
 *   -F-c         ->    -F-f-c
 *     `c                 `N`c
 */
static inline int
break_fork(npos_t p, int b, npos_t t, npos_t n)
{
	npos_t r;
	npos_t f;

	f = new_fork(CHILD(t, 0), CHILD(t, 1));
	if (f == 0)
		return LPM_FAIL;

	r = new_fork(f, n);
	if (r == 0)
		return LPM_FAIL;
	ADDR(r)  = ADDR(t);
	MASK(r)  = MASK(t);
	RELAY(r) = RELAY(t);

	atomic_replace(p, b, r);
	return LPM_OK;
}

static int
add_route(npos_t root, npos_t add, int move)
{
	npos_t p = root;
	npos_t t = CHILD(root, 0);
	npos_t c;
	int b = 0;
	int bb;

	/* root node */
	if (check_cidr(ADDR(add), MASK(add), ADDR(t), MASK(t)) != LPM_OK) {
		/* unmatch */
		return add_fork(root, 0, t, add);
	}
	if (MASK(add) < MASK(t)) {
		/* match and short */
		if (RELAY(t) == 0) {
			return update_node(root, 0, t, add);
		} else {
			return insert_node(root, 0, t, add);
		}
	}

	while(t) {
		/* match node */
		if (ADDR(t) == ADDR(add) && MASK(t) == MASK(add)) {
			if (move) {
				move_relay(t, add);
				del_broadcast(root);
			} else {
				add_relay(t, add);
			}
			return LPM_OK;
		}

		/* leaf node */
		if (CHILD(t, 0) == 0) {
			return add_leaf(p, b, t, add);
		}

		/* fork node */
		bb = 0;
		if (FORKBIT(t)) {
			IP_t a = ADDR(CHILD(t, 0));
			uint8_t m = FORKBIT(t) -1;
			if (check_cidr(ADDR(add), MASK(add), a, m) != LPM_OK) {
				/* unmatch */
				return break_fork(p, b, t, add);
			}
			if (MASK(add) < FORKBIT(t)) {
				/* match and short */
				return insert_mixed(p, b, t, add);
			}
			/* match and long */
			bb = get_forkbit(ADDR(add), FORKBIT(t));
		}

		/* child node */
		c = CHILD(t, bb);
		if (check_cidr(ADDR(add), MASK(add),
			       ADDR(c), MASK(c)) != LPM_OK) {
			/* unmatch */
			if (FORKBIT(t)) {
				return add_fork(t, bb, c, add);
			} else {
				return add_leaf(p, b, t, add);
			}
		}
		if (MASK(add) < MASK(c)) {
			/* match and short */
			if (RELAY(c) == 0) {
				return update_node(t, bb, c, add);
			} else {
				return insert_node(t, bb, c, add);
			}
		}
		/* match and long */
		p = t;
		t = c;
		b = bb;
	}

	/* NOTREACHED */
	return LPM_FAIL;
}

static int
add_or_move_rule(vxid_t vni, npos_t add, int move)
{
	uint32_t h = calc_hash(vni, IP_PROTO);
	npos_t root;

	root = hash[h];
	while (root) {
		if (VNI(root) == vni && PROTO(root) == PROTO(add)) {
			if (add_broadcast(root, add) == 0)
				return LPM_FAIL;
			if (add_route(root, add, move) != LPM_OK) {
				release_node(add);
				del_broadcast(root);
			}
			return LPM_OK;
		}
		root = CHILD(root, 1);
	}

	/*
	 *  add new root
	 */
	root = get_node();
	if (root == 0)
		return LPM_FAIL;

	TYPE(root)     = LPM_TYPE_ROOT;
	PROTO(root)    = PROTO(add);
	VNI(root)      = vni;
	CHILD(root, 0) = add;
	CHILD(root, 1) = hash[h];
	if (add_broadcast(root, add) == 0)
		return LPM_FAIL;

	mfence();
	hash[h] = root;
	set_wild_card(vni, root);
	mfence();
	unmark_update(root);

	return LPM_OK;
}

int
IP_FUNC(LPM_add_rule)(vxid_t vni, npos_t add) {
	return add_or_move_rule(vni, add, 0);
}

int
IP_FUNC(LPM_move_rule)(vxid_t vni, npos_t add) {
	return add_or_move_rule(vni, add, 1);
}

/*
 *  delete rules
 */

/*
 *   root-C       ->     ()
 *
 *   -s-C         ->    -s
 *
 *   -f-C         ->    -c
 *     `c
 *
 *   -m-C         ->    -s-c
 *     `c
 *
 *   -m-f-c       ->    -m-c
 *     `C`c               `c
 *
 */
static inline int
del_leaf(npos_t pp, int bb, npos_t p, int b, npos_t t)
{
	mark_update(t);

	if (TYPE(p) == LPM_TYPE_ROOT) {
		return LPM_FAIL;
	} else if (CHILD(p, 1) == 0) {
		atomic_set(p, b, 0);
	} else if (RELAY(p) == 0) {
		mark_update(p);
		atomic_set(pp, bb, CHILD(p, 1 - b));
		release_node(p);
	} else if (RELAY(CHILD(p, 1 - b))) {
		npos_t n = new_node(ADDR(p), MASK(p), RELAY(p));
		if (n == 0)
			return LPM_FAIL;

		mark_update(p);
		CHILD(n, 0) = CHILD(p, 1 - b);
		atomic_set(pp, bb, n);
		release_node(p);
	} else {
		npos_t f = new_fork(CHILD(CHILD(p, 1 - b), 0),
				    CHILD(CHILD(p, 1 - b), 1));
		if (f == 0)
			return LPM_FAIL;

		mark_update(p);
		ADDR(f)  = ADDR(p);
		MASK(f)  = MASK(p);
		RELAY(f) = RELAY(p);
		atomic_set(pp, bb, f);
		release_node(p);
	}

	release_node(t);
	return LPM_OK;
}

/*
 *   -S-c         ->     -c
 */
static inline int
del_node(npos_t p, int b, npos_t t)
{
	mark_update(t);
	atomic_set(p, b, CHILD(t, 0));
	release_node(t);

	return LPM_OK;
}

/*
 *   -M-c         ->    -f-c
 *     `c                 `c
 *
 *   -s-M-c       ->    -m-c
 *       `c               `c
 *
 */
static inline int
del_mixed(npos_t pp, int bb, npos_t p, int b, npos_t t)
{
	npos_t f = new_fork(CHILD(t, 0), CHILD(t, 1));

	if (f == 0)
		return LPM_FAIL;

	mark_update(t);
	if (TYPE(p) != LPM_TYPE_ROOT && CHILD(p, 1) == 0) {
		mark_update(p);
		ADDR(f)  = ADDR(p);
		MASK(f)  = MASK(p);
		RELAY(f) = RELAY(p);
		atomic_set(pp, bb, f);
		release_node(p);
	} else {
		atomic_set(p, b, f);
	}
	release_node(t);

	return LPM_OK;
}

static int
del_route(npos_t root, npos_t del)
{
	npos_t p = root;
	npos_t t = CHILD(root, 0);
	npos_t pp = 0;
	int b = 0;
	int bb = 0;

	while(t) {
		if (check_cidr(ADDR(del), MASK(del),
			       ADDR(t), MASK(t)) != LPM_OK)
			return LPM_OK;

		if (ADDR(del) == ADDR(t) && MASK(del) == MASK(t))
			break;

		bb = b;
		b = 0;

		if (FORKBIT(t)) {
			IP_t    a = ADDR(CHILD(t, 0));
			uint8_t m = FORKBIT(t) -1;
			if (check_cidr(ADDR(del), MASK(del), a, m) != LPM_OK) {
				/* unmatch */
				return LPM_OK;
			}
			if (MASK(del) < FORKBIT(t)) {
				/* match and short */
				return LPM_OK;
			}
			/* match and long */
			b = get_forkbit(ADDR(del), FORKBIT(t));
		}

		pp = p;
		p = t;
		t = CHILD(t, b);
	}

	if (t == 0)
		return LPM_OK;
	if (del_relay(t, del) == LPM_OK)
		return LPM_OK;
	if (CHILD(t, 0) == 0)
		return del_leaf(pp, bb, p, b, t);
	if (CHILD(t, 1) == 0)
		return del_node(p, b, t);

	return del_mixed(pp,bb, p, b, t);
}

void
IP_FUNC(LPM_delete_rule)(vxid_t vni, npos_t del)
{
	uint32_t h = calc_hash(vni, IP_PROTO);
	npos_t root = hash[h];
	npos_t *pp = &hash[h];

	while (root) {
		if (VNI(root) == vni && PROTO(root) == PROTO(del)) {
			if (del_route(root, del) != LPM_OK) {
				/*
				 *  delete root
				 */
				mark_update(CHILD(root, 0));
				mark_update(root);
				mfence();
				set_wild_card(vni, 0);
				*pp = CHILD(root, 1);
				mfence();
				release_node(CHILD(root, 0));
				release_node(root);
			} else {
				del_broadcast(root);
			}
			release_node(del);
			return;
		}
		pp = &CHILD(root, 1);
		root = CHILD(root, 1);
	}
	release_node(del);
}

/*
 *  flush rules
 */
void
IP_FUNC(LPM_flush_rule)(vxid_t vni)
{
	uint32_t h = calc_hash(vni, IP_PROTO);
	npos_t root = hash[h];
	npos_t *pp = &hash[h];

	while (root) {
		if (VNI(root) == vni && PROTO(root) == IP_PROTO) {
			/*
			 *  delete tree and root
			 */
			mark_update_tree(CHILD(root, 0));
			mark_update(root);
			mfence();
			set_wild_card(vni, 0);
			*pp = CHILD(root, 1);
			mfence();
			release_tree(CHILD(root, 0));
			release_node(root);

			return;
		}
		pp = &CHILD(root, 1);
		root = CHILD(root, 1);
	}
}

void
IP_FUNC(LPM_update_rule)(vxid_t work_vni, vxid_t vni)
{
	uint32_t h = calc_hash(work_vni, IP_PROTO);
	npos_t root = hash[h];
	npos_t *pp = &hash[h];
	npos_t work;

	/*
	 *  search work root
	 */
	while (root) {
		if (VNI(root) == work_vni && PROTO(root) == IP_PROTO) {
			mark_update_tree(CHILD(root, 0));
			mark_update(root);
			mfence();
			*pp = CHILD(root, 1);
			mfence();
			break;
		}
		pp = &CHILD(root, 1);
		root = CHILD(root, 1);
	}
	work = root;
	if (work)
		VNI(work) = vni;

	/*
	 *  search target root
	 */
	h = calc_hash(vni, IP_PROTO);
	root = hash[h];
	pp = &hash[h];
	while (root) {
		if (VNI(root) == vni && PROTO(root) == IP_PROTO) {
			mark_update_tree(CHILD(root, 0));
			mark_update(root);
			if (work) {
				/*
				 *  update root
				 */
				CHILD(work, 1) = CHILD(root, 1);
				mfence();
				*pp = work;
				set_wild_card(vni, work);
				mfence();
				unmark_update_tree(CHILD(work, 0));
				unmark_update(work);
			} else {
				/*
				 *  delete VNI
				 */
				mfence();
				set_wild_card(vni, 0);
				*pp = CHILD(root, 1);
				mfence();
			}
			release_tree(CHILD(root, 0));
			release_node(root);
			return;
		}
		pp = &CHILD(root, 1);
		root = CHILD(root, 1);
	}

	/*
	 *  add root
	 */
	CHILD(work, 1) = hash[h];
	mfence();
	hash[h] = work;
	set_wild_card(vni, work);
	mfence();
	unmark_update_tree(CHILD(work, 0));
	unmark_update(work);
}

/*
 *  find rule
 */
static npos_t
find_route_relay(npos_t root, IP_t addr)
{
	npos_t t = CHILD(root, 0);
	npos_t r = 0;
	int b = 0;

	if (check_cidr(addr, IPsize, ADDR(t), MASK(t)) != LPM_OK)
		return r;

	while(t) {
		IP_t    a = ADDR(CHILD(t, 0));
		uint8_t m = FORKBIT(t) -1;

		if (RELAY(t))
			r = RELAY(t);

		b = 0;
		if (FORKBIT(t)) {
			if (check_cidr(addr, IPsize, a, m) != LPM_OK) {
				/* unmatch */
				return r;
			}
			/* match */
			b = get_forkbit(addr, FORKBIT(t));
		}

		t = CHILD(t, b);
		if (check_cidr(addr, IPsize, ADDR(t), MASK(t)) != LPM_OK)
			return r;
	}

	return r;
}

static inline npos_t
find_route(npos_t root, IP_t addr)
{
	npos_t r = find_route_relay(root, addr);
	npos_t n;

	for (n = RELAY(r); n; n = RELAY(n)) {
		if (PROTO(n) == PROTO_IP4
		    && V4ADDR(n) == LPM_RELAY_Drop)
			return 0;
		if (PROTO(n) == PROTO_IP4
		    && V4ADDR(n) == LPM_RELAY_Broadcast)
			return RELAY(root);
	}

	return r;
}

npos_t
IP_FUNC(LPM_find_urelay)(vxid_t vni, IP_t addr)
{
	uint32_t h = calc_hash(vni, IP_PROTO);
	npos_t root;

	root = hash[h];
	while (root) {
		if (VNI(root) == vni && PROTO(root) == IP_PROTO)
			return find_route(root, addr);
		root = CHILD(root, 1);
	}

	if (CHILD(0, IP_WILD_CARD))
		return find_route(CHILD(0, IP_WILD_CARD), addr);

	return 0;
}

npos_t
IP_FUNC(LPM_find_mrelay)(vxid_t vni)
{
	uint32_t h = calc_hash(vni, IP_PROTO);
	npos_t root;

	root = hash[h];
	while (root) {
		if (VNI(root) == vni && PROTO(root) == IP_PROTO)
			return RELAY(root);
		root = CHILD(root, 1);
	}

	if (CHILD(0, IP_WILD_CARD))
		return RELAY(CHILD(0, IP_WILD_CARD));

	return 0;
}

/*
 *  access functions
 */
npos_t
IP_FUNC(LPM_set_access_node)(IP_t addr, uint8_t mask)
{
	npos_t n = get_node();
	if (n == 0)
		return 0;

	TYPE(n)  = LPM_TYPE_NODE;
	PROTO(n) = IP_PROTO;
	ADDR(n)  = addr & IPmask[mask];
	MASK(n)  = mask;
	RELAY(n) = 0;

	return n;
}

int
IP_FUNC(LPM_set_access_relay)(npos_t node, IP_t addr)
{
	npos_t r;
	npos_t n;

	for (r = RELAY(node); r; r = RELAY(r))
		if (PROTO(r) == IP_PROTO && ADDR(r) == addr)
			return LPM_OK;

	n = get_node();
	if (n == 0)
		return LPM_FAIL;

	TYPE(n)  = LPM_TYPE_RELAY;
	PROTO(n) = IP_PROTO;
	ADDR(n)  = addr;
	MASK(n)  = IPsize;
	RELAY(n) = RELAY(node);

	RELAY(node) = n;
	return LPM_OK;
}

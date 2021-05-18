/*
 *  lpm.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "ioutil.h"
#include "logging.h"
#include "lpm.h"
#include "lpm_internal.h"

static int fd;
static int lpm_file_opened = 0;
static int lpm_file_locked = 0;
static int lpm_file_mapped = 0;
static int lpm_mem_locked = 0;

static unsigned char *map = NULL;
struct lpm_header *header = NULL;
struct lpm_data *pool = NULL;
npos_t *hash = NULL;

static inline rlim_t
mlock_limit(rlim_t need)
{
	struct rlimit rlim;

	/*
	 *  get resource limit
	 */
	if (getrlimit(RLIMIT_MEMLOCK, &rlim))
		error_exit("getllimit failed: %s", strerror(errno));
	debug("rlmit(MEMLOCK) cur=%lu, max=%lu, need=%lu",
	      rlim.rlim_cur, rlim.rlim_max, need);

	if (rlim.rlim_cur < need) {
		/*
		 *  try expand resource limit
		 */
		rlim.rlim_cur = need;
		if (rlim.rlim_max < need)
			rlim.rlim_max = need;
		setrlimit(RLIMIT_MEMLOCK, &rlim); /* ignore error */

		/*
		 *  re-get resource limit
		 */
		if (getrlimit(RLIMIT_MEMLOCK, &rlim))
			error_exit("getllimit failed: %s", strerror(errno));
		debug("rlmit(MEMLOCK) cur=%lu, max=%lu, need=%lu",
		      rlim.rlim_cur, rlim.rlim_max, need);
	}

	return rlim.rlim_cur;
}

static inline void
lpm_mlock(uint32_t size)
{
	if (lpm_mem_locked)
		return;

	/*
	 *  check resource limit
	 */
	if (mlock_limit(size) < size)
		return;

	/*
	 *  memory lock
	 */
	if (mlock(map, size) < 0)
		error_exit("rule mlock failed: %s", strerror(errno));
	else
		debug("rule memory locked");

	lpm_mem_locked = 1;
}

static inline void
lpm_munlock(uint32_t size)
{
	if (lpm_mem_locked == 0)
		return;

	/*
	 *  memory unlock
	 */
	if (munlock(map, size) < 0)
		error_exit("rule munlock failed: %s", strerror(errno));
	else
		debug("rule memory unlocked");

	lpm_mem_locked = 0;
}

void
LPM_lock_rules()
{
	struct flock lock;
	if (lpm_file_locked)
		return;

	/*
	 *  file lock
	 */
	memset(&lock, 0, sizeof(struct flock));
	lock.l_type   = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start  = 0;
	lock.l_len    = 0;
	if (fcntl(fd, F_SETLKW, &lock))
		error_exit("rule fcntl lock failed: %s", strerror(errno));
	else
		debug("rule locked");

	lpm_file_locked = 1;
}

void
LPM_unlock_rules()
{
	struct flock lock;

	if (lpm_file_locked == 0)
		return;

	/*
	 *  file unlock
	 */
	mfence();
	memset(&lock, 0, sizeof(struct flock));
	lock.l_type   = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start  = 0;
	lock.l_len    = 0;
	if (fcntl(fd, F_UNLCK, &lock))
		error_exit("rule fcntl unlock failed: %s", strerror(errno));
	else
		debug("rule unlocked");

	lpm_file_locked = 0;
}

void
LPM_sync_rules()
{
	if (msync(map, header->file_size, MS_SYNC) == 0)
		debug("rule memory synced");
}

void
LPM_init_rules(char *filename, uint32_t pool_size, uint32_t hash_size)
{
	struct lpm_header h;
	unsigned char data_buf[DATA_BUF_SIZE];
	uint32_t i;

	/*
	 *  initialize header info
	 */
	memset((void*)h.buffer, 0, LPM_HEADER_SIZE);
	h.magic       = OCTOPI_RULE_MAGIC;
	h.version     = OCTOPI_RULE_VERSION;
	h.header_size = LPM_HEADER_SIZE;
	h.node_size   = sizeof(struct lpm_data);
	h.npos_size   = sizeof(npos_t);
	h.pool_size   = pool_size;
	h.hash_size   = hash_size;
	h.data_size   = h.node_size * pool_size + h.npos_size * hash_size;
	h.file_size   = h.header_size + h.data_size;
	h.pool_head   = 0;
	h.pool_tail   = 0;

	/*
	 *  open file
	 */
	if (lpm_file_opened || lpm_file_mapped)
		error_exit("rule failed: duplicate open");
	fd = open(filename, O_RDWR | O_CREAT | O_EXCL | O_NOATIME, 0644);
	if (fd < 0) {
		error_exit("rule open failed: %s: %s",
			   filename, strerror(errno));
	} else {
		lpm_file_opened = 1;
		debug("rule opened");
	}

	/*
	 *  file lock
	 */
	LPM_lock_rules();

	/*
	 *  write initial header
	 */
	if (xwrite(fd, h.buffer, LPM_HEADER_SIZE) != LPM_HEADER_SIZE)
		error_exit("rule write header failed: %s: %s",
			   filename, strerror(errno));

	/*
	 *  zero initalize data
	 */
	memset(data_buf, 0, DATA_BUF_SIZE);
	for (i = 0; i < h.data_size; i += DATA_BUF_SIZE)
		if (xwrite(fd, data_buf, DATA_BUF_SIZE) != DATA_BUF_SIZE)
			error_exit("rule write data failed: %s: %s",
				   filename, strerror(errno));

	/*
	 *  memory map
	 */
	map = (unsigned char *)mmap(NULL, h.file_size, PROT_READ | PROT_WRITE,
				    MAP_SHARED, fd, 0);
	if (map == (unsigned char *)MAP_FAILED) {
		error_exit("rule mmap failed: %s: %s",
			   filename, strerror(errno));
	} else {
		debug("rule memory mapped");
		lpm_file_mapped = 1;
	}

	header = (struct lpm_header *)map;
	pool = (struct lpm_data *)(map + LPM_HEADER_SIZE);
	hash = (npos_t *)(map + LPM_HEADER_SIZE
			  + header->node_size * header->pool_size);

	/*
	 *  memory lock
	 */
	lpm_mlock(header->file_size);

	/*
	 *  initialzie base
	 */
	TYPE(0) = LPM_TYPE_BASE;

	/*
	 *  initialize pool
	 */
	for (i = 1; i < pool_size; ++ i)
		put_node(i);
}

void
LPM_open_rules(char *filename, int flag)
{
	struct lpm_header h;
	int port;

	/*
	 *  check opened
	 */
	if (lpm_file_opened && lpm_file_mapped)
		return;

	fd = open(filename, flag);
	if (fd < 0) {
		error_exit("rule open failed: %s: %s",
			   filename, strerror(errno));
	} else {
		lpm_file_opened = 1;
		debug("rule opened");
	}

	/*
	 *  file lock
	 */
	if (flag != O_RDONLY)
		LPM_lock_rules();

	/*
	 *  read header
	 */
	if (xread(fd, h.buffer, LPM_HEADER_SIZE) != LPM_HEADER_SIZE)
		error_exit("rule read header failed: %s: %s",
			   filename, strerror(errno));

	/*
	 *  check magic
	 */
	if (h.magic != OCTOPI_RULE_MAGIC) {
		if (h.magic == OCTOPI_RULE_REVMAGIC) {
			error_exit("rule invalid endian");
		} else {
			error_exit("rule invalid file");
		}
	}

	/*
	 *  check version
	 */
	if ((h.version >> 32) != (OCTOPI_RULE_VERSION >> 32))
		error_exit("rule invalid version");

	/*
	 *  memory map
	 */
	if (flag == O_RDONLY) {
		port = PROT_READ;
	} else {
		port = PROT_READ | PROT_WRITE;
	}
	map = (unsigned char *)mmap(NULL, h.file_size, port,
				    MAP_SHARED, fd, 0);
	if (map == (unsigned char *)MAP_FAILED) {
		error_exit("rule mmap failed: %s: %s",
			   filename, strerror(errno));
	} else {
		lpm_file_mapped = 1;
		debug("rule memory mapped");
	}
	header = (struct lpm_header *)map;
	pool = (struct lpm_data *)(map + LPM_HEADER_SIZE);
	hash = (npos_t *)(map + LPM_HEADER_SIZE
			  + header->node_size * header->pool_size);

	/*
	 *  memory lock
	 */
	lpm_mlock(header->file_size);

	/*
	 *  close file if read only
	 */
	if (flag == O_RDONLY) {
		if (close(fd) < 0) {
			error_exit("rule close failed: %s", strerror(errno));
		} else {
			lpm_file_opened = 0;
			debug("rule closed");
		}
	}
}

void
LPM_close_rules()
{
	if (lpm_file_mapped) {
		/*
		 *  memory unlock
		 */
		lpm_munlock(header->file_size);

		/*
		 *  memory unmap
		 */
		if (munmap(map, header->file_size) < 0) {
			error_exit("rule munmap failed: %s", strerror(errno));
		} else {
			lpm_file_mapped = 0;
			map = NULL;
			pool = NULL;
			hash = NULL;
			debug("rule memory unmapped");
		}
	}

	if (lpm_file_opened) {
		/*
		 *  unlock
		 */
		LPM_unlock_rules();

		/*
		 *  close file
		 */
		if (close(fd) < 0) {
			error_exit("rule close failed: %s", strerror(errno));
		} else {
			lpm_file_opened = 0;
			fd = -1;
			debug("rule closed");
		}
	}
}

void
LPM_open_or_init_rules(char *filename, int flag,
		       uint32_t pool_size, uint32_t hash_size)
{
	if (access(filename, F_OK) < 0) {
		LPM_init_rules(filename, pool_size, hash_size);
		LPM_close_rules();
	}
	LPM_open_rules(filename, flag);
}

void
LPM_reinit_rules(char *filename, uint32_t pool_size, uint32_t hash_size)
{
	/*
	 *  remove old file
	 */
	if (unlink(filename) < -1 && errno != ENOENT)
		error_exit("rule unlink failed: %s: %s",
			   filename, strerror(errno));

	return LPM_init_rules(filename, pool_size, hash_size);
}

void
LPM_unset_access_node(npos_t node)
{
	if (node)
		release_node(node);
}

int
LPM_get_next_relay(npos_t *np, ADDR* a)
{
	npos_t n = *np;

	if (n == 0 || TYPE(n) != LPM_TYPE_RELAY)
		return LPM_FAIL;

	if (PROTO(n) == PROTO_IP4) {
		a->af        = AF_INET;
		a->mask      = MASK(n);
		a->ipv4_addr = pool[n].ipv4_addr;
	} else if (PROTO(n) == PROTO_IP6) {
		a->af        = AF_INET6;
		a->mask      = MASK(n);
		a->ipv6_addr = pool[n].ipv6_addr;
	} else {
		return LPM_FAIL;
	}

	*np = RELAY(*np);
	return LPM_OK;
}


int
LPM_add_rule(uint32_t vni, npos_t node)
{
	if (PROTO(node) == PROTO_IP4)
		return LPM_add_rule_ip4(vni, node);
	if (PROTO(node) == PROTO_IP6)
		return LPM_add_rule_ip6(vni, node);
	return LPM_OK;
}

void
LPM_delete_rule(uint32_t vni, npos_t node)
{
	if (PROTO(node) == PROTO_IP4)
		LPM_delete_rule_ip4(vni, node);
	else if (PROTO(node) == PROTO_IP6)
		LPM_delete_rule_ip6(vni, node);
}

int
LPM_move_rule(uint32_t vni, npos_t node)
{
	if (PROTO(node) == PROTO_IP4)
		return LPM_move_rule_ip4(vni, node);
	else if (PROTO(node) == PROTO_IP6)
		return LPM_move_rule_ip6(vni, node);

	return LPM_OK;
}

void
LPM_flush_rule(uint32_t vni, uint8_t proto)
{
	if (proto & PROTO_IP4)
		LPM_flush_rule_ip4(vni);
	if (proto & PROTO_IP6)
		LPM_flush_rule_ip6(vni);
}

void
LPM_update_rule(uint32_t work_vni, uint32_t vni, uint8_t proto)
{
	if (proto & PROTO_IP4)
		LPM_update_rule_ip4(work_vni, vni);
	if (proto & PROTO_IP6)
		LPM_update_rule_ip6(work_vni, vni);
}

void
LPM_restore_start(uint8_t proto)
{
	uint32_t i;
	npos_t h;

	for (i = 0; i < header->hash_size; ++ i)
		for (h = hash[i]; h; h = CHILD(h, 1))
			if (PROTO(h) & proto && VNI(h) != VNI_ALL)
				mark_restore(h);
}

void
LPM_restore_finish(uint8_t proto)
{
	uint32_t i;

	for (i = 0; i < header->hash_size; ++ i) {
		npos_t root = hash[i];
		npos_t *pp = &hash[i];

		while (root) {
			if ((PROTO(root) & proto) && test_restore(root)) {
				mark_update_tree(CHILD(root, 0));
				mark_update(root);
				mfence();
				*pp = CHILD(root, 1);
				mfence();
				unmark_restore(root);
				release_tree(CHILD(root, 0));
				release_node(root);
			} else {
				pp = &CHILD(root, 1);
			}
			root = CHILD(root, 1);
		}
	}
}

void
LPM_restore_abort(uint8_t proto)
{
	uint32_t i;
	npos_t h;

	for (i = 0; i < header->hash_size; ++ i)
		for (h = hash[i]; h; h = CHILD(h, 1))
			if (PROTO(h) & proto)
				unmark_restore(h);
}

static void
fsck_used()
{
	uint32_t i;
	npos_t root;
	npos_t n;
	npos_t prev;
	npos_t r;

	/*
	 *  mark used to all tree
	 */
	for (i = 0; i < header->hash_size; ++ i) {
		for (root = hash[i]; root; root = CHILD(root, 1)) {
			for (r = RELAY(root); r; r = RELAY(r))
				mark_used(r);
			mark_used_tree(CHILD(root, 0));
			mark_used(root);
		}
	}

	/*
	 *  remove used node from pool
	 */
	prev = 0;
	for (n = header->pool_head; n; n = NEXT(n)) {
		if (test_used(n)) {
			if (n == header->pool_tail)
				header->pool_tail = prev;
			if (prev)
				NEXT(prev) = NEXT(n);
			else
				header->pool_head = NEXT(n);
		} else {
			prev = n;
		}
	}

	/*
	 *  unmark used to all tree
	 */
	for (i = 0; i < header->hash_size; ++ i) {
		for (root = hash[i]; root; root = CHILD(root, 1)) {
			for (r = RELAY(root); r; r = RELAY(r))
				unmark_used(r);
			unmark_used_tree(CHILD(root, 0));
			unmark_used(root);
		}
	}
}

void
LPM_fsck_rule(int all)
{
	uint32_t i;
	npos_t root;
	npos_t n;
	npos_t tail = header->pool_head;
	npos_t r;

	if (all) {
		/*
		 *  remove used node from pool
		 */
		fsck_used();

		/*
		 *  update mark all node
		 */
		for (i = 1; i < header->pool_size; ++ i)
			mark_update(i);
	}

	/*
	 *  fix base
	 */
	if (TYPE(0) != LPM_TYPE_BASE) {
		TYPE(0) = LPM_TYPE_BASE;
		NEXT(0) = 0;
		MARK(0) = 0;
	}

	/*
	 *  unmark all tree node
	 */
	for (i = 0; i < header->hash_size; ++ i) {
		for (root = hash[i]; root; root = CHILD(root, 1)) {
			for (r = RELAY(root); r; r = RELAY(r))
				unmark_all(r);
			unmark_all_tree(CHILD(root, 0));
			unmark_all(root);
		}
	}

	/*
	 *  ummark all pool node
	 */
	for (n = header->pool_head; n; n = NEXT(n)) {
		tail = n;
		unmark_all(n);
	}
	header->pool_tail = tail;

	/*
	 *  put back update marked node
	 */
	for (i = 1; i < header->pool_size; ++ i) {
		if (test_update(i)) {
			put_node(i);
		}
	}
}

void
LPM_pause(int n)
{
	if (n)
		header->pause = 1;
	else
		header->pause = 0;
}

int
LPM_check_pause()
{
	if (header->pause)
		return LPM_FAIL;

	return LPM_OK;
}

void
LPM_queue_sync(int n)
{
	if (n)
		header->queue_sync = 1;
	else
		header->queue_sync = 0;
}

int
LPM_check_queue_sync()
{
	return header->queue_sync;
}

uint8_t
LPM_get_proto(npos_t n)
{
	return PROTO(n);
}

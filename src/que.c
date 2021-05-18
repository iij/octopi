/*
 *  que.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "ioutil.h"
#include "logging.h"
#include "que.h"
#include "que_internal.h"

enum {
	FALSE = 0,
	TRUE  = 1,
};

static int fd;
static int que_file_opened = 0;
static int que_file_locked = 0;
static int que_file_mapped = 0;

static unsigned char *map = NULL;
struct que_header *q_header = NULL;
struct que_data *q_pool = NULL;
qpos_t *q_hash = NULL;

uint32_t
QUE_calc_addr_hash(ADDR *a)
{
	uint32_t h = 2166136261;
	int len = 4;
	int i;

	if (a->af == AF_INET6)
		len = 16;
	for (i = 0; i < len; ++ i) {
		h ^= a->addr[i];
		h *= 16777619;
	}

	return h % q_header->hash_size;
}

uint64_t
QUE_now()
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (uint64_t) tv.tv_sec;
}

void
QUE_lock()
{
	struct flock lock;

	if (que_file_locked)
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
		error_exit("fcntl lock failed: %s", strerror(errno));
	else
		debug("queue file locked");

	que_file_locked = 1;
}

void
QUE_unlock()
{
	struct flock lock;

	if (que_file_locked == 0)
		return;

	/*
	 *  file unlock
	 */
	memset(&lock, 0, sizeof(struct flock));
	lock.l_type   = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start  = 0;
	lock.l_len    = 0;
	if (fcntl(fd, F_UNLCK, &lock))
		error_exit("queue fcntl unlock failed: %s",   strerror(errno));
	else
		debug("queue file unlocked");

	que_file_locked = 0;
}

void
QUE_disk_sync()
{
	if (msync(map, q_header->file_size, MS_SYNC) == 0)
		debug("queue memory synced");
}

void
QUE_init(char *filename, uint32_t pool_size, uint32_t hash_size)
{
	struct que_header h;
	unsigned char data_buf[QUE_BUF_SIZE];
	uint32_t i;

	/*
	 *  initialize queue header
	 */
	memset((void*)h.buffer, 0, QUE_HEADER_SIZE);
	h.magic       = OCTOPI_QUE_MAGIC;
	h.version     = OCTOPI_QUE_VERSION;
	h.header_size = QUE_HEADER_SIZE;
	h.node_size   = sizeof(struct que_data);
	h.qpos_size   = sizeof(qpos_t);
	h.pool_size   = pool_size;
	h.hash_size   = hash_size;
	h.data_size   = h.node_size * pool_size + h.qpos_size * hash_size;
	h.file_size   = h.header_size + h.data_size;
	h.pool_head   = 0;
	h.pool_tail   = 0;

	/*
	 *  open file
	 */
	if (que_file_opened || que_file_mapped)
		error_exit("queue init failed: duplicate open");
	fd = open(filename, O_RDWR | O_CREAT | O_EXCL | O_NOATIME, 0644);
	if (fd < 0) {
		error_exit("open failed: %s: %s", filename, strerror(errno));
	} else {
		que_file_opened = 1;
		debug("queue file opened");
	}

	/*
	 *  file lock
	 */
	 QUE_lock();

	 /*
	  *  write initial header
	  */
	 if (xwrite(fd, h.buffer, QUE_HEADER_SIZE) != QUE_HEADER_SIZE)
		 error_exit("queue write header failed: %s: %s",
			    filename, strerror(errno));

	 /*
	  *  zero initalize data
	  */
	 memset(data_buf, 0, QUE_BUF_SIZE);
	 for (i = 0; i < h.data_size; i += QUE_BUF_SIZE)
		 if (xwrite(fd, data_buf, QUE_BUF_SIZE) != QUE_BUF_SIZE)
			 error_exit("queue write data failed: %s: %s",
				    filename, strerror(errno));

	 /*
	  *  memory map
	  */
	 map = (unsigned char *)mmap(NULL, h.file_size, PROT_READ | PROT_WRITE,
				     MAP_SHARED, fd, 0);
	 if (map == (unsigned char *)MAP_FAILED) {
		 error_exit("queue mmap failed: %s: %s",
			    filename, strerror(errno));
	 }  else {
		 que_file_mapped = 1;
		 debug("queue memory mapped");
	 }

	 q_header = (struct que_header *)map;
	 q_pool = (struct que_data *)(map + QUE_HEADER_SIZE);
	 q_hash = (qpos_t *)(map + QUE_HEADER_SIZE
			     + q_header->node_size * q_header->pool_size);

	 /*
	  *  initialzie backup node
	  */
	 TYPE(BACKUP_NODE) = QUE_TYPE_BACKUP;
	 INSERT_TIME(BACKUP_NODE) = QUE_now();
	 UPDATE_TIME(BACKUP_NODE) = INSERT_TIME(BACKUP_NODE);

	 /*
	  *  initialize pool
	  */
	 for (i = 1; i < pool_size; ++ i)
		 put_node(i);

	/*
	 *  file unlock
	 */
	 QUE_unlock();
}

void
QUE_open(char *filename, int flag)
{
	struct que_header h;
	int port;

	/*
	 *  check opened
	 */
	if (que_file_opened || que_file_mapped)
		return;

	fd = open(filename, flag);
	if (fd < 0) {
		error_exit("queue open failed: %s: %s",
			   filename, strerror(errno));
	} else {
		que_file_opened = 1;
		debug("queue file opened");
	}

	/*
	 *  read header
	 */
	if (xread(fd, h.buffer, QUE_HEADER_SIZE) != QUE_HEADER_SIZE)
		error_exit("queue read header failed: %s: %s",
			   filename, strerror(errno));

	/*
	 *  check magic
	 */
	if (h.magic != OCTOPI_QUE_MAGIC) {
		if (h.magic == OCTOPI_QUE_REVMAGIC) {
			error_exit("queue invalid endian");
		} else {
			error_exit("queue invalid file");
		}
	}

	/*
	 *  check version
	 */
	if ((h.version >> 32) != (OCTOPI_QUE_VERSION >> 32))
		error_exit("queue invalid version");

	/*
	 *  memory map
	 */
	if (flag == O_RDONLY) {
		port = PROT_READ;
	} else {
		port = PROT_READ|PROT_WRITE;
	}
	map = (unsigned char *)mmap(NULL, h.file_size, port,
				    MAP_SHARED, fd, 0);
	if (map == (unsigned char *)MAP_FAILED) {
		error_exit("queue mmap failed: %s: %s",
			   filename, strerror(errno));
	} else {
		que_file_mapped = 1;
		debug("queue memory mapped");
	}

	q_header = (struct que_header *)map;
	q_pool = (struct que_data *)(map + QUE_HEADER_SIZE);
	q_hash = (qpos_t *)(map + QUE_HEADER_SIZE
			    + q_header->node_size * q_header->pool_size);
}

void
QUE_close()
{
	if (que_file_mapped) {
		/*
		 *  memory unmap
		 */
		if (munmap(map, q_header->file_size) < 0) {
			error_exit("queue munmap failed: %s", strerror(errno));
		} else {
			que_file_mapped = 0;
			map = NULL;
			q_pool = NULL;
			q_hash = NULL;
			debug("queue memory unmapped");
		}
	}

	if (que_file_opened) {
		/*
		 *  unlock
		 */
		QUE_unlock();

		/*
		 *  close file
		 */
		if (close(fd) < 0) {
			error_exit("queue close failed: %s", strerror(errno));
		} else {
			que_file_opened = 0;
			fd = -1;
			debug("queue file closed");
		}
	}
}

void
QUE_open_or_init(char *filename, int flag,
		 uint32_t pool_size, uint32_t hash_size)
{
	if (access(filename, F_OK) < 0) {
		QUE_init(filename, pool_size, hash_size);
		QUE_close();
	}
	QUE_open(filename, flag);
}

void
QUE_reinit(char *filename, uint32_t pool_size, uint32_t hash_size)
{
	/*
	 *  remove old file
	 */
	if (unlink(filename) < -1 && errno != ENOENT)
		error_exit("queue unlink failed: %s: %s",
			   filename, strerror(errno));

	return QUE_init(filename, pool_size, hash_size);
}

static int
QUE_new_queue(qpos_t mem, vxid_t vni)
{
	uint32_t update = UPDATE(mem) + 1;
	qpos_t q;

	q = get_node();
	if (q == 0)
		return QUE_FAIL;
	
	/* setup new queue */
	TYPE(q)          = QUE_TYPE_QUEUE;
	PROTO(q)         = PROTO_ALL;
	VNI(q)           = vni;
	UPDATE(q)        = update;
	INSERT_TIME(q)   = QUE_now();
	UPDATE_TIME(q)   = INSERT_TIME(q);
	QUEUE(q)         = QUEUE(mem);

	/* push to relay */
	if (QUEUE(mem) == 0) {
		INSERT_TIME(mem) = INSERT_TIME(q);
		UPDATE_TIME(mem) = UPDATE_TIME(q);
	}
	QUEUE(mem) = q;
	UPDATE(mem) = update;
	unmark_update(q);

	return QUE_OK;
}

void
QUE_delete_all_queue(qpos_t mem)
{
	qpos_t q;
	qpos_t prev = mem;

	for (q = QUEUE(mem); q; q = QUEUE(q)) {
		mark_update(q);
		QUEUE(prev) = QUEUE(q);
		put_node(q);
	}
	SYNC(mem) = UPDATE(mem);
	ACTION(mem) = 0;
}

qpos_t
QUE_find_member(qpos_t relay, ADDR *m)
{
	qpos_t mem;

	for (mem = MEMBER(relay); mem; mem = MEMBER(mem)) {
		if (match_qaddr(mem, m))
			break;
	}

	return mem;
}

static qpos_t
QUE_new_member(ADDR *m)
{
	uint32_t h;
	qpos_t mem;

	/* check address family */
	if (m->af != AF_INET && m->af != AF_INET6)
		return 0;
	
	/* allocate */
	mem = get_node();
	if (mem == 0)
		return 0;

	/* set parameter */
	TYPE(mem)           = QUE_TYPE_MEMBER;
	if (m->af == AF_INET) {
		PROTO(mem)  = PROTO_IP4;
		V4ADDR(mem) = m->ipv4_addr;
	} else {
		PROTO(mem)  = PROTO_IP6;
		V4ADDR(mem) = m->ipv6_addr;		
	}
	UPDATE(mem)         = 0;
	INSERT_TIME(mem)    = QUE_now();
	UPDATE_TIME(mem)    = INSERT_TIME(mem);

	/* push ALL vni */
	if (QUE_new_queue(mem, VNI_ALL) == QUE_FAIL) {
		put_node(mem);
		return 0;
	}

	/* link to hash */
	h = QUE_calc_addr_hash(m);
	LINK(mem)           = q_hash[h];
	q_hash[h]           = mem;

	return mem;
}

static void
QUE_delete_hash_link(qpos_t mem)
{
	ADDR addr;
	qpos_t h;
	qpos_t l;
	qpos_t *prev;

	/*
	 *  calc hash
	 */
	if (PROTO(mem) == PROTO_IP4) {
		addr.af        = AF_INET;
		addr.ipv4_addr = V4ADDR(mem);
	} else if (PROTO(mem) == PROTO_IP6) {
		addr.af   = AF_INET6;
		addr.ipv6_addr = V6ADDR(mem);
	} else {
		abort();
	}
	h = QUE_calc_addr_hash(&addr);

	/*
	 *  remove link
	 */
	prev = q_hash + h;
	for (l = q_hash[h]; l; l = LINK(l)) {
		if (l == mem) {
			*prev = LINK(l);
			break;
		}
		prev = &LINK(l);
	}
}

static void
QUE_delete_member(qpos_t relay, ADDR *m)
{
	qpos_t mem;
	qpos_t prev = relay;

	for (mem = MEMBER(relay); mem; mem = MEMBER(mem)) {
		if (match_qaddr(mem, m))
			break;
		prev = mem;
	}

	/*
	 *  not found
	 */
	if (mem == 0)
		return;

	/*
	 *  delete member
	 */
	UPDATE_TIME(relay) = QUE_now();
	mark_update(mem);
	QUE_delete_all_queue(mem);
	MEMBER(prev) = MEMBER(mem);
	QUE_delete_hash_link(mem);
	put_node(mem);
}

static void
QUE_delete_all_member(qpos_t relay)
{
	if (MEMBER(relay))
		UPDATE_TIME(relay) = QUE_now();
	while (MEMBER(relay)) {
		qpos_t mem = MEMBER(relay);

		mark_update(mem);
		QUE_delete_all_queue(mem);
		MEMBER(relay) = MEMBER(mem);
		QUE_delete_hash_link(mem);
		put_node(mem);
	}
}

qpos_t
QUE_find_relay(ADDR *r)
{
	qpos_t h = QUE_calc_addr_hash(r);
	qpos_t relay;

	for (relay = q_hash[h]; relay; relay = LINK(relay)) {
		if (TYPE(relay) == QUE_TYPE_RELAY) {
			if (match_qaddr(relay, r))
				break;
		}
	}

	return relay;
}

static qpos_t
QUE_new_relay(ADDR *r)
{
	qpos_t relay;
	uint32_t h;

	/* check address family */
	if (r->af != AF_INET && r->af != AF_INET6)
		return 0;

	/* allocate */
	relay = get_node();
	if (relay == 0)
		return 0;

	/* set parameter */
	TYPE(relay)        = QUE_TYPE_RELAY;
	if (r->af == AF_INET) {
		PROTO(relay)       = PROTO_IP4;
		V4ADDR(relay)      = r->ipv4_addr;	
	} else {
		PROTO(relay)       = PROTO_IP6;
		V6ADDR(relay)      = r->ipv6_addr;
	}
	UPDATE(relay)      = 0;
	INSERT_TIME(relay) = QUE_now();
	UPDATE_TIME(relay) = INSERT_TIME(relay);

	/* link to hash */
	h = QUE_calc_addr_hash(r);
	LINK(relay)        = q_hash[h];
	q_hash[h]          = relay;
	unmark_update(relay);

	return relay;
}

static void
QUE_delete_relay(ADDR *r)
{
	qpos_t h = QUE_calc_addr_hash(r);
	qpos_t *prev = q_hash + h;
	qpos_t relay;

	for (relay = q_hash[h]; relay; relay = LINK(relay)) {
		if (TYPE(relay) == QUE_TYPE_RELAY) {
			if (match_qaddr(relay, r))
				break;
		}
		prev = &LINK(relay);
		relay = LINK(relay);
	}

	/*
	 *  not found
	 */
	if (relay == 0)
		return;

	/*
	 *  delete relayess from hash
	 */
	mark_update(relay);
	*prev = LINK(relay);
	put_node(relay);
}

int
QUE_node_add(ADDR *r, ADDR *m)
{
	qpos_t relay = QUE_find_relay(r);

	if (relay == 0)
		relay = QUE_new_relay(r);

	if (relay == 0)
		return QUE_FAIL;

	if (QUE_find_member(relay, m) == 0) {
		qpos_t mem = QUE_new_member(m);
		if (mem == 0) {
			if (MEMBER(relay) == 0)
				QUE_delete_relay(r);
			return QUE_FAIL;
		}

		/* link to relay */
		RELAY(mem)          = relay;
		MEMBER(mem)         = MEMBER(relay);
		MEMBER(relay)       = mem;
		UPDATE_TIME(relay)  = UPDATE_TIME(mem);
		unmark_update(mem);
	}

	return QUE_OK;
}

int
QUE_node_delete(ADDR *r, ADDR *m)
{
	qpos_t relay = QUE_find_relay(r);

	if (relay == 0)
		return QUE_OK;

	if (m == NULL)
		QUE_delete_all_member(relay);
	else
		QUE_delete_member(relay, m);

	if (MEMBER(relay) == 0)
		QUE_delete_relay(r);

	return QUE_OK;
}

int
QUE_backup_add(ADDR *m)
{
	if (QUE_find_member(BACKUP_NODE, m) == 0) {
		qpos_t relay = BACKUP_NODE;
		qpos_t mem = QUE_new_member(m);
		if (mem == 0) {
			return QUE_FAIL;
		}

		/* link to backp */
		RELAY(mem)          = relay;
		MEMBER(mem)         = MEMBER(relay);
		MEMBER(relay)       = mem;
		UPDATE_TIME(relay)  = UPDATE_TIME(mem);
		unmark_update(mem);
	}

	return QUE_OK;
}

int
QUE_backup_delete(ADDR *m)
{
	if (m == NULL)
		QUE_delete_all_member(BACKUP_NODE);
	else
		QUE_delete_member(BACKUP_NODE, m);

	return QUE_OK;
}

static int
QUE_queue_push(qpos_t mem, vxid_t vni)
{
	qpos_t q;

	/*
	 *  check all
	 */
	if (vni == VNI_ALL)
		QUE_delete_all_queue(mem);

	/*
	 *  search queue
	 */
	for (q = QUEUE(mem); q; q = QUEUE(q)) {
		if (VNI(q) == vni) {
			UPDATE_TIME(q) = QUE_now();
			return QUE_OK;
		}
	}

	/*
	 *  new queue
	 */
	if (QUE_new_queue(mem, vni) == QUE_FAIL)
		return QUE_FAIL;

	return QUE_OK;
}

static int
QUE_queue_relay_push(qpos_t relay, vxid_t vni)
{
	qpos_t mem;

	for (mem = MEMBER(relay); mem; mem = MEMBER(mem)) {
		if (QUE_queue_push(mem, vni) != QUE_OK)
			return QUE_FAIL;
	}

	return QUE_OK;
}

static int
QUE_queue_member_add(ADDR *m, vxid_t vni)
{
	qpos_t h = QUE_calc_addr_hash(m);
	qpos_t mem;

	for (mem = q_hash[h]; mem; mem = LINK(mem)) {
		if (TYPE(mem) == QUE_TYPE_MEMBER && match_qaddr(mem, m)) {
			if (QUE_queue_push(mem, vni) != QUE_OK)
				return QUE_FAIL;
		}
	}

	return QUE_OK;
}

int
QUE_queue_add(int utype, ADDR *t, vxid_t vni)
{
	int done = 0;
	qpos_t relay;

	switch (utype) {
	case QUE_UPDATE_AUTO:
	case QUE_UPDATE_RELAY:
	case QUE_UPDATE_BOTH:
		if (t == NULL) {
			relay = BACKUP_NODE;
		} else {
			relay = QUE_find_relay(t);
			if (relay == 0)
				break;
		}
		if (QUE_queue_relay_push(relay, vni) != QUE_OK)
			return QUE_FAIL;
		done = 1;
		break;
	default:
		break;
	}

	switch (utype) {
	case QUE_UPDATE_AUTO:
		if (done)
			break;
		/* FALLTHROUGH */
	case QUE_UPDATE_MEMBER:
	case QUE_UPDATE_BOTH:
		if (t != NULL)
			if (QUE_queue_member_add(t, vni) != QUE_OK)
				return QUE_FAIL;
		break;
	default:
		break;
	}

	return QUE_OK;
}

int
QUE_queue_add_all(vxid_t vni)
{
	uint32_t h;
	qpos_t mem;

	for (h = 0; h < q_header->hash_size; ++ h) {
		for (mem = q_hash[h]; mem; mem = LINK(mem)) {
			if (TYPE(mem) != QUE_TYPE_MEMBER)
				continue;
			if (QUE_queue_push(mem, vni) != QUE_OK)
				return QUE_FAIL;
		}
	}

	return QUE_OK;
}

static void
QUE_queue_pull(qpos_t mem, vxid_t vni)
{
	qpos_t q;
	qpos_t prev = mem;

	if (vni == VNI_ALL) {
		/*
		 *  delete all
		 */
		QUE_delete_all_queue(mem);
	} else {
		/*
		 *  search queue
		 */
		for (q = QUEUE(mem); q; q = QUEUE(q)) {
			if (VNI(q) == vni) {
				mark_update(q);
				QUEUE(prev) = QUEUE(q);
				put_node(q);
				break;
			}
			prev = mem;
		}
	}

	/* update time if empty */
	if (QUEUE(mem) == 0)
		UPDATE_TIME(mem) = QUE_now();
}

static void
QUE_queue_relay_pull(qpos_t relay, vxid_t vni)
{
	qpos_t mem;

	for (mem = MEMBER(relay); mem; mem = MEMBER(mem)) {
		QUE_queue_pull(mem, vni);
	}
}

static void
QUE_queue_member_delete(ADDR *m, vxid_t vni)
{
	qpos_t h = QUE_calc_addr_hash(m);
	qpos_t mem;

	for (mem = q_hash[h]; mem; mem = LINK(mem)) {
		if (TYPE(mem) == QUE_TYPE_MEMBER && match_qaddr(mem, m)) {
			QUE_queue_pull(mem, vni);
		}
	}
}

void
QUE_queue_delete(int utype, ADDR *t, vxid_t vni)
{
	int done = 0;
	qpos_t relay;

	switch (utype) {
	case QUE_UPDATE_AUTO:
	case QUE_UPDATE_RELAY:
	case QUE_UPDATE_BOTH:
		if (t == NULL) {
			relay = BACKUP_NODE;
		} else {
			relay = QUE_find_relay(t);
			if (relay == 0)
				break;
		}
		QUE_queue_relay_pull(relay, vni);
		done = 1;
		break;
	default:
		break;
	}

	switch (utype) {
	case QUE_UPDATE_AUTO:
		if (done)
			break;
		/* FALLTHROUGH */
	case QUE_UPDATE_MEMBER:
	case QUE_UPDATE_BOTH:
		if (t != NULL)
			QUE_queue_member_delete(t, vni);
		break;
	default:
		break;
	}
}

void
QUE_queue_delete_all(vxid_t vni)
{
	uint32_t h;
	qpos_t mem;

	for (h = 0; h < q_header->hash_size; ++ h) {
		for (mem = q_hash[h]; mem; mem = LINK(mem)) {
			if (TYPE(mem) != QUE_TYPE_MEMBER)
				continue;
			QUE_queue_pull(mem, vni);
		}
	}
}

MLIST *
QUE_init_mlist(int max)
{
	MLIST *p = malloc(sizeof(MLIST));

	if (p == NULL)
		return NULL;
	p->num  = 0;
	p->size = max;
	p->pos  = 0;

	p->member = malloc(max * sizeof(qpos_t));
	if (p->member == NULL) {
		free(p);
		return NULL;
	}

	return p;
}

void
QUE_free_mlist(MLIST *p)
{
	free(p->member);
	free(p);
}

static void
QUE_mlist_push(MLIST *p, qpos_t mem)
{
	int i;

	if (p == NULL)
		return;

	/*
	 *  check already registered
	 */
	for (i = 0; i < p->num; ++ i)
		if (p->member[i] == mem)
			return;

	/*
	 *  check full
	 */
	if (p->num >= p->size) {
		int size = p->size * 2;
		qpos_t *member = realloc(p->member, size * sizeof(qpos_t));
		if (member == NULL)
			return;
		p->member = member;
		p->size   = size;
	}

	/*
	 *  set member
	 */
	p->member[p->num ++] = mem;
}

static void
QUE_check_sync(MLIST *p, qpos_t mem)
{
	if (TYPE(mem) != QUE_TYPE_MEMBER)
		return;

	if (QUEUE(mem) == 0)
		return;

	if (SYNC(mem) >= UPDATE(mem))
		return;

	if (ACTION(mem))
		return;

	QUE_mlist_push(p, mem);
}

static void
QUE_get_sync_member(MLIST *p, ADDR *m)
{
	qpos_t h = QUE_calc_addr_hash(m);
	qpos_t mem;

	for (mem = q_hash[h]; mem; mem = LINK(mem)) {
		if (TYPE(mem) == QUE_TYPE_MEMBER && match_qaddr(mem, m)) {
			QUE_check_sync(p, mem);
			break;
		}
	}
}

static void
QUE_get_sync_relay(MLIST *p, qpos_t relay)
{
	qpos_t mem;

	for (mem = MEMBER(relay); mem; mem = MEMBER(mem))
		QUE_check_sync(p, mem);
}

static int
cmp_update(const void *p1, const void *p2)
{
	qpos_t a = *(qpos_t*)p1;
	qpos_t b = *(qpos_t*)p2;

	if (UPDATE_TIME(a) > UPDATE_TIME(b))
		return 1;
	else if (UPDATE_TIME(a) < UPDATE_TIME(b))
		return -1;

	return 0;
}

MLIST *
QUE_get_sync_list(MLIST *p, int utype, ADDR *t)
{
	int done = 0;
	qpos_t relay;

	if (p == NULL)
		p = QUE_init_mlist(128);
	if (p == NULL)
		return NULL;
	
	switch (utype) {
	case QUE_UPDATE_AUTO:
	case QUE_UPDATE_RELAY:
	case QUE_UPDATE_BOTH:
		if (t == NULL) {
			relay = BACKUP_NODE;
		} else {
			relay = QUE_find_relay(t);
			if (relay == 0)
				break;
		}
		QUE_get_sync_relay(p, relay);
		done = 1;
		break;
	default:
		break;
	}

	switch (utype) {
	case QUE_UPDATE_AUTO:
		if (done)
			break;
		/* FALLTHROUGH */
	case QUE_UPDATE_MEMBER:
	case QUE_UPDATE_BOTH:
		QUE_get_sync_member(p, t);
		break;
	default:
		break;
	}

	qsort(p->member, p->num, sizeof(qpos_t), cmp_update);

	return p;
}

MLIST *
QUE_get_sync_list_all(MLIST *p)
{
	uint32_t i;

	if (p == NULL)
		p = QUE_init_mlist(4096);
	if (p == NULL)
		return NULL;
	
	p->num = 0;
	p->pos = 0;

	QUE_get_sync_relay(p, BACKUP_NODE);
	for (i = 0; i < q_header->hash_size; ++ i) {
		qpos_t relay;
		for (relay = q_hash[i]; relay; relay = LINK(relay)) {
			if (TYPE(relay) == QUE_TYPE_RELAY)
				QUE_get_sync_relay(p, relay);
		}
	}
	qsort(p->member, p->num, sizeof(qpos_t), cmp_update);

	return p;
}

void
QUE_member_addr(qpos_t mem, ADDR *a)
{
	memset((void*)a, 0, sizeof(ADDR));

	if (TYPE(mem) != QUE_TYPE_MEMBER)
		return;

	if (PROTO(mem) == PROTO_IP4) {
		a->af = AF_INET;
		a->ipv4_addr = V4ADDR(mem);
	} else if (PROTO(mem) == PROTO_IP6) {
		a->af = AF_INET6;
		a->ipv6_addr = V6ADDR(mem);
	}
}

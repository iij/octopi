/*
 *  lpm_output.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "addrutil.h"
#include "logging.h"
#include "lpm.h"
#include "lpm_internal.h"

enum {
	FALSE = 0,
	TRUE  = 1,
};

static int
cmp_uint64(const void *p1, const void *p2)
{
	uint64_t a = *(uint64_t*)p1;
	uint64_t b = *(uint64_t*)p2;

	if (a > b)
		return 1;
	else if (a < b)
		return -1;

	return 0;
}

static int
LPM_check_relay(npos_t n, ADDR *a)
{
	npos_t r;

	for (r = RELAY(n); r; r = RELAY(r)) {
		if (a->af == AF_INET && PROTO(r) == PROTO_IP4) {
			if (a->ipv4_addr == V4ADDR(r))
				return 1;
		} else if (a->af == AF_INET6 && PROTO(r) == PROTO_IP6) {
			if (a->ipv6_addr == V6ADDR(r))
				return 1;
		}
	}

	return 0;
}

uint32_t
LPM_listup_roots(uint8_t proto, uint64_t **data, ADDR *a)
{
	npos_t h;
	npos_t n;
	int len = 4096;
	uint32_t count = 0;
	uint64_t *list = (uint64_t *)malloc(len * sizeof(uint64_t));

	if (list == NULL)
		crit_exit("out of memory ... aborted");

	/*
	 *  list all hash
	 */
	for (h = 0; h < header->hash_size; ++ h) {
		/*
		 *   list all root node
		 */
		for (n = hash[h]; n; n = pool[n].child[1]) {
			/*
			 *  check vni
			 */
			if (VNI(n) != VNI_ANY && VNI(n) > MAX_VNI)
				continue;

			/*
			 *  check protocol
			 */
			if ((PROTO(n) & proto) == 0)
				continue;

			/*
			 *  check relay address
			 */
			if (a && LPM_check_relay(n, a) == 0)
				continue;

			/*
			 *  check list length
			 */
			if (count == len) {
				len *= 2;
				list = (uint64_t *)
					realloc(list, len * sizeof(uint64_t));
				if (list == NULL)
					crit_exit("out of memory ... aborted");
			}

			/*
			 *  store VNI and proto
			 */
			list[count ++] = ((uint64_t)VNI(n)) << 8 | PROTO(n);
		}
	}

	/*
	 *  sort VNI list
	 */
	qsort(list, count, sizeof(uint64_t), cmp_uint64);

	*data = list;
	return count;
}

void
LPM_free_roots(uint64_t *list)
{
	free(list);
}

void
LPM_disp_vni(IOBUF *buf, char *fmt, vxid_t vni)
{
	char vnum[16];
	const char *str = vnum;

	switch (vni) {
	case VNI_ALL:
		str = "all";
		break;
	case VNI_ACL:
		str = "acl";
		break;
	case VNI_ANY:
		str = "any";
		break;
	case VNI_WORK:
		str = "work";
		break;
	case VNI_INVALID:
		str = "invalid";
		break;
	default:
		sprintf(vnum, "%u", vni);
	}

	zprintf(buf, fmt, str);
}

void
LPM_disp_target(IOBUF *buf, npos_t n)
{
	char addrbuf[IP_STR_LEN];
	char *addr = addrbuf;

	if (PROTO(n) == PROTO_IP4) {
		if (V4ADDR(n) == 0 && MASK(n) == 0) {
			zprintf(buf, "default");
		} else {
			if (ip4_to_str(&V4ADDR(n), addr) == FALSE)
				addr = "unknown";
			zprintf(buf, "%s/%d",  addr, MASK(n));
		}
	} else if (PROTO(n) == PROTO_IP6) {
		if (V6ADDR(n) == 0 && MASK(n) == 0) {
			zprintf(buf, "default6");
		} else {
			if (ip6_to_str(&V6ADDR(n), addr) == FALSE)
				addr = "unknown6";
			zprintf(buf, "%s/%d",  addr, MASK(n));
		}
	} else {
		zprintf(buf, "unknown_addr/%d",  MASK(n));
	}
}

void
LPM_disp_relay(IOBUF *buf, npos_t relay)
{
	npos_t n ;
	char addrbuf[IP_STR_LEN];
	char *addr;

	for (n = relay; n; n = RELAY(n)) {
		addr = addrbuf;
		if (PROTO(n) == PROTO_IP4) {
			if (V4ADDR(n) == LPM_RELAY_Drop)
				addr = "drop";
			else if (V4ADDR(n) == LPM_RELAY_Broadcast)
				addr = "broadcast";
			else if (ip4_to_str(&V4ADDR(n), addr) == FALSE)
				addr = "unknown";
		} else if (PROTO(n) == PROTO_IP6) {
			if (ip6_to_str(&V6ADDR(n), addr) == FALSE)
				addr = "unknown";
		} else
			continue;
		zprintf(buf, " %s", addr);
	}
	zprintf(buf, "\n");
}

static void
LPM_show_node(IOBUF *buf, int indent, npos_t n)
{
	int i;

	/*
	 *  indent
	 */
	for (i = 0; i < indent; ++i)
		zprintf(buf, " ");

	/*
	 *  show node
	 */
	zprintf(buf, "node ");

	/*
	 *  target
	 */
	LPM_disp_target(buf, n);

	/*
	 *  forkbit
	 */
	zprintf(buf, "  fork %d", FORKBIT(n));

	/*
	 *  relay
	 */
	if (RELAY(n)) {
		zprintf(buf, "  unicast");
		LPM_disp_relay(buf, RELAY(n));
	} else {
		zprintf(buf, "\n");
	}

	/*
	 *  show childs
	 */
	if (CHILD(n, 0))
		LPM_show_node(buf, indent + 1, CHILD(n, 0));
	if (CHILD(n, 1))
		LPM_show_node(buf, indent + 1, CHILD(n, 1));
}

static int
LPM_show_root(IOBUF *buf, int vni_tag, uint32_t vni, uint8_t proto)
{
	uint32_t h = calc_hash(vni, proto);
	npos_t root;

	for (root = hash[h]; root; root = CHILD(root, 1)) {
		if (VNI(root) == vni && PROTO(root) == proto) {
			if (vni_tag) {
				LPM_disp_vni(buf, "vni %s\n", vni);
				vni_tag = 0;
			}
			zprintf(buf, " root proto %s  multicast",
			       proto==PROTO_IP4 ?"IPv4" :"IPv6");
			LPM_disp_relay(buf, RELAY(root));
			LPM_show_node(buf, 2, CHILD(root, 0));
			return vni_tag;
		}
	}
	return vni_tag;
}

void
LPM_show(IOBUF *buf, uint32_t vni, uint8_t proto)
{
	int vni_tag = 1;
	if (proto & PROTO_IP4)
		vni_tag = LPM_show_root(buf, vni_tag, vni, PROTO_IP4);
	if (proto & PROTO_IP6)
		vni_tag = LPM_show_root(buf, vni_tag, vni, PROTO_IP6);
}

static void
LPM_list_node(IOBUF *buf, char *name, vxid_t vni, npos_t n)
{
	/*
	 *  list node
	 */
	if (RELAY(n)) {
		zprintf(buf, "%s add ", name);
		LPM_disp_vni(buf, "%s ", vni);
		LPM_disp_target(buf, n);
		LPM_disp_relay(buf, RELAY(n));
	}

	/*
	 *  list childs
	 */
	if (CHILD(n, 0))
		LPM_list_node(buf, name, vni, CHILD(n, 0));
	if (CHILD(n, 1))
		LPM_list_node(buf, name, vni, CHILD(n, 1));
}

static void
LPM_list_root(IOBUF *buf, char *name, uint32_t vni, uint8_t proto)
{
	uint32_t h = calc_hash(vni, proto);
	npos_t root;

	for (root = hash[h]; root; root = CHILD(root, 1)) {
		if (VNI(root) == vni && PROTO(root) == proto) {
			LPM_list_node(buf, name, vni, CHILD(root, 0));
			return;
		}
	}
}

void
LPM_list(IOBUF *buf, char *name, uint32_t vni, uint8_t proto)
{
	if (proto & PROTO_IP4)
		LPM_list_root(buf, name, vni, PROTO_IP4);
	if (proto & PROTO_IP6)
		LPM_list_root(buf, name, vni, PROTO_IP6);
}

static void
LPM_save_node(IOBUF *buf, npos_t n)
{
	/*
	 *  save node
	 */
	if (RELAY(n)) {
		LPM_disp_target(buf, n);
		LPM_disp_relay(buf, RELAY(n));
	}

	/*
	 *  save childs
	 */
	if (CHILD(n, 0))
		LPM_save_node(buf, CHILD(n, 0));
	if (CHILD(n, 1))
		LPM_save_node(buf, CHILD(n, 1));
}

int
LPM_save_root(IOBUF *buf, int vni_tag, uint32_t vni, uint8_t proto)
{
	uint32_t h = calc_hash(vni, proto);
	npos_t root;

	for (root = hash[h]; root; root = CHILD(root, 1)) {
		if (VNI(root) == vni && PROTO(root) == proto) {
			if (vni_tag) {
				LPM_disp_vni(buf, "rule %s\n", vni);
				vni_tag = 0;
			}
			LPM_save_node(buf, CHILD(root, 0));
			return vni_tag;
		}
	}
	return vni_tag;
}

void
LPM_save(IOBUF *buf, uint32_t vni, uint8_t proto)
{
	int vni_tag = 1;

	if (proto & PROTO_IP4)
		vni_tag = LPM_save_root(buf, vni_tag, vni, PROTO_IP4);
	if (proto & PROTO_IP6)
		vni_tag = LPM_save_root(buf, vni_tag, vni, PROTO_IP6);
	if (vni_tag == 0)
		zprintf(buf, "commit\n");
}

static void
LPM_list_acl_node(IOBUF *buf, char *name, ip4_t action, npos_t n)
{
	/*
	 *  list node
	 */
	if (RELAY(n)) {
		npos_t r = RELAY(n);
		if (PROTO(r) == PROTO_IP4 && V4ADDR(r) == action) {
			zprintf(buf,"%s acl add ", name);
			LPM_disp_target(buf, n);
			if (action == LPM_ACL_Deny)
				zprintf(buf, " deny\n");
			else if (action == LPM_ACL_Accept)
				zprintf(buf, " allow\n");
			else
				zprintf(buf, " unknown\n");
		}
	}

	/*
	 *  list childs
	 */
	if (CHILD(n, 0))
		LPM_list_acl_node(buf, name, action, CHILD(n, 0));
	if (CHILD(n, 1))
		LPM_list_acl_node(buf, name, action, CHILD(n, 1));
}

static void
LPM_list_acl_root(IOBUF *buf, char *name, uint8_t proto, ip4_t action)
{
	uint32_t h = calc_hash(VNI_ACL, proto);
	npos_t root;

	for (root = hash[h]; root; root = CHILD(root, 1)) {
		if (VNI(root) == VNI_ACL && PROTO(root) == proto) {
			LPM_list_acl_node(buf, name, action, CHILD(root, 0));
			return;
		}
	}
}

void
LPM_list_acl(IOBUF *buf, char *name, uint8_t proto)
{
	if (proto & PROTO_IP4)
		LPM_list_acl_root(buf, name, PROTO_IP4, LPM_ACL_Deny);
	if (proto & PROTO_IP4)
		LPM_list_acl_root(buf, name, PROTO_IP4, LPM_ACL_Accept);
	if (proto & PROTO_IP6)
		LPM_list_acl_root(buf, name, PROTO_IP6, LPM_ACL_Deny);
	if (proto & PROTO_IP6)
		LPM_list_acl_root(buf, name, PROTO_IP6, LPM_ACL_Accept);
}

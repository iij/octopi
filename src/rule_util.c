/*
 *  rule_util.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "octopi.h"
#include "addrutil.h"
#include "logging.h"
#include "lpm.h"
#include "que.h"
#include "rule.h"

void
open_rule_file(OD *od, int flag)
{
	/*
	 *  oepn octopi rule
	 */
	if (!od->dryrun)
		LPM_open_rules(od->rule_file, flag);
}

void
init_rule_file(OD *od, uint32_t pool_size, uint32_t hash_size)
{
	/*
	 *  check dryrun
	 */
	if (od->dryrun)
		return;

	/*
	 *  init octopi rule
	 */
	LPM_init_rules(od->rule_file, pool_size, hash_size);

	/*
	 *  close octopi rule
	 */
	LPM_close_rules();

	/*
	 *  change rule owner
	 */
	if (geteuid() == 0)
		if (chown(od->rule_file, od->user, od->group) < 0)
			/* ignore error */ ;
}

void
close_rule_file(OD *od)
{
	if (!od->dryrun)
		LPM_close_rules();
}

void
sync_rule_file(OD *od)
{
	if (!od->dryrun)
		LPM_sync_rules();
}

void
open_queue_file(OD *od, int flag)
{
	/*
	 *  check dryrun
	 */
	if (od->dryrun)
		return;

	/*
	 *  oepn queue
	 */
	QUE_open(od->queue_file, flag);

	/*
	 *  lock queue
	 */
	if (flag & O_RDWR)
		QUE_lock();
}

void
init_queue_file(OD *od, uint32_t pool_size, uint32_t hash_size)
{
	/*
	 *  check dryrun
	 */
	if (od->dryrun)
		return;

	/*
	 *  init queue file
	 */
	QUE_init(od->queue_file, pool_size, hash_size);

	/*
	 *  close queue
	 */
	QUE_close();

	/*
	 *  change queue owner
	 */
	if (geteuid() == 0)
		if (chown(od->queue_file, od->user, od->group) < 0)
			/* ignore error */ ;
}

void
close_queue_file(OD *od)
{
	/*
	 *  check dryrun
	 */
	if (od->dryrun)
		return;

	/*
	 *  unlock queue
	 */
	QUE_unlock();

	/*
	 *  sync to disk
	 */
	QUE_disk_sync();

	/*
	 *  close queue
	 */
	QUE_close();
}

int
conv_vni(char *src, uint32_t *vni, char **err)
{
	if (strcasecmp(src, "all") == 0) {
		*vni = VNI_ALL;
		return TRUE;
	}
	if (strcasecmp(src, "any") == 0) {
		*vni = VNI_ANY;
		return TRUE;
	}
	if (str_to_uint32(src, vni) == FALSE) {
		*err = "vni must be a number or \"any\"";
		return FALSE;
	}
	if (*vni > MAX_VNI) {
		*err = "vni is too large";;
		return FALSE;
	}

	return TRUE;
}

int
conv_proto(char *src, uint8_t *proto, char **err)
{
	if (strcasecmp(src, "ipv4") == 0) {
		*proto = PROTO_IP4;
	} else if (strcasecmp(src, "ipv6") == 0) {
		*proto = PROTO_IP6;
	} else if (strcasecmp(src, "all") == 0) {
		*proto = PROTO_ALL;
	} else {
		*err = "protocol must be ipv4 or ipv6 or all";
		return FALSE;
	}

	return TRUE;
}

int
conv_target(char *src, npos_t *node, int dryrun, char **err)
{
	ADDR addr;

	/*
	 *  convert target address
	 */
	if (strcasecmp(src, "default") == 0) {
		addr.af = AF_INET;
		addr.ipv4_addr = 0;
		addr.mask = 0;
	} else if (strcasecmp(src, "default6") == 0) {
		addr.af = AF_INET6;
		addr.ipv6_addr = 0;
		addr.mask = 0;
	} else if (str_to_cidr(src, &addr) == FALSE) {
		*err = "target must be addr[/mask]";
		return FALSE;
	}

	/*
	 *  check dryrun
	 */
	if (dryrun)
		return TRUE;

	/*
	 *  assign node
	 */
	if (addr.af == AF_INET)
		*node = LPM_set_access_node_ip4(addr.ipv4_addr, addr.mask);
	else
		*node = LPM_set_access_node_ip6(addr.ipv6_addr, addr.mask);

	if (*node == 0) {
		*err = "rule space is empty";
		return FALSE;
	}

	return TRUE;
}

int
conv_relay(npos_t node, char *src, int dryrun, char **err)
{
	ADDR relay;
	int rst;

	/*
	 *  convert target address
	 */
	if (strcasecmp(src, "drop") == 0) {
		relay.af = AF_INET;
		relay.ipv4_addr = LPM_RELAY_Drop;
		relay.mask = 32;
	} else if (strcasecmp(src, "broadcast") == 0) {
		relay.af = AF_INET;
		relay.ipv4_addr = LPM_RELAY_Broadcast;
		relay.mask = 32;
	} else if (str_to_addr(src, &relay) == FALSE) {
		*err = "relay must be addr";
		if (!dryrun)
			LPM_unset_access_node(node);
		return FALSE;
	}

	/*
	 *  check dryrun
	 */
	if (dryrun)
		return TRUE;

	/*
	 *  assign to access node
	 */
	if (relay.af == AF_INET) {
		rst = LPM_set_access_relay_ip4(node, relay.ipv4_addr);
	} else {
		rst = LPM_set_access_relay_ip6(node, relay.ipv6_addr);
	}
	if (rst != LPM_OK){
		*err = "rule space is empty";
		LPM_unset_access_node(node);
		return FALSE;
	}

	return TRUE;
}

int
conv_relays(npos_t node, int ac, char **av, int dryrun, char **err)
{
	int i;

	for (i = 0; i < ac; ++ i) {
		if (conv_relay(node, av[i], dryrun, err) == FALSE)
			return FALSE;
	}

	return TRUE;
}

int
conv_acl(npos_t node, char *src, int dryrun, char **err)
{
	ip4_t acl;
	int rst;

	/*
	 *  convert target address
	 */
	if (strcasecmp(src, "deny") == 0) {
		acl = LPM_ACL_Deny;
	} else if (strcasecmp(src, "allow") == 0) {
		acl = LPM_ACL_Accept;
	} else {
		*err = "acl must be \"allow\" or \"deny\"";
		return FALSE;
	}

	/*
	 *  check dryrun
	 */
	if (dryrun)
		return TRUE;

	/*
	 *  assign ACL node
	 */
	rst = LPM_set_access_relay_ip4(node, acl);
	if (rst != LPM_OK){
		*err = "rule space is empty";
		LPM_unset_access_node(node);
		return FALSE;
	}

	return TRUE;
}

int
conv_que_update(char *src, int *type)
{
	if (strcasecmp(src, "auto") == 0) {
		*type = QUE_UPDATE_AUTO;
		return QUE_OK;
	} else if (strcasecmp(src, "relay") == 0) {
		*type = QUE_UPDATE_RELAY;
		return QUE_OK;
	} else if (strcasecmp(src, "member") == 0) {
		*type = QUE_UPDATE_MEMBER;
		return QUE_OK;
	} else if (strcasecmp(src, "both") == 0) {
		*type = QUE_UPDATE_BOTH;
		return QUE_OK;
	}

	return QUE_FAIL;
}

static ADDR *
append_qrelay(ADDR *relay_list, ADDR *relay)
{
	ADDR *r;
	ADDR *new;

	/*
	 *  check already listed
	 */
	for (r = relay_list; r; r = r->next) {
		if (addr_match(r, relay))
			return relay_list;
	}

	/*
	 *  allocate new relay
	 */
	new = malloc(sizeof(ADDR));
	if (new == NULL)
		crit_exit("out of memory ... aborted");

	/*
	 *  set parameter
	 */
	memset(new, 0, sizeof(ADDR));
	new->next = relay_list;
	new->af   = relay->af;
	if (relay->af == AF_INET) {
		new->ipv4_addr = relay->ipv4_addr;
	} else { /* AF_INET6 */
		new->ipv6_addr = relay->ipv6_addr;
	}

	return new;
}

QRELAY *
init_qrelay(OD *od)
{
	QRELAY *qr;

	/*
	 *  check queue sync enable
	 */
	if (od->dryrun || LPM_check_queue_sync() == 0)
		return NULL;

	/*
	 *  allocate memory
	 */
	qr = malloc(sizeof(QRELAY));
	if (qr == NULL)
		crit_exit("out of memory ... aborted");

	/*
	 *  initialize
	 */
	qr->relay = NULL;

	return qr;
}

static void
get_qrelay_vni(QRELAY *qr, vxid_t vni)
{
	npos_t n;

	/*
	 *  check queue sync enable
	 */
	if (qr == NULL)
		return;

	/*
	 *  setup IPv4 target
	 */
	 n = LPM_find_mrelay_ip4(vni);
	 while (n) {
		 ADDR relay;
		 LPM_get_next_relay(&n, &relay);
		 qr->relay = append_qrelay(qr->relay, &relay);
	 }

	/*
	 *  setup IPv6 target
	 */
	 n = LPM_find_mrelay_ip6(vni);
	 while (n) {
		 ADDR relay;
		 LPM_get_next_relay(&n, &relay);
		 qr->relay = append_qrelay(qr->relay, &relay);
	 }
}

void
get_qrelay(OD *od, QRELAY *qr, vxid_t vni)
{
	uint64_t *list;
	uint32_t n;

	/*
	 *  check queue sync enable
	 */
	if (qr == NULL)
		return;

	/*
	 *  search and store queue relay
	 */
	if (vni == VNI_ALL) {
		uint32_t count = LPM_listup_roots(PROTO_ALL, &list, NULL);
		for (n = 0; n < count; ++ n) {
			uint32_t vni = list[n] >> 8;
			get_qrelay_vni(qr, vni);
		}
		LPM_free_roots(list);
	} else {
		get_qrelay_vni(qr, vni);
	}
}

void
push_qrelay(OD *od, QRELAY *qr, vxid_t vni)
{
	ADDR *r;

	/*
	 *  check queue sync enable
	 */
	if (qr == NULL)
		return;

	/*
	 *  open queue
	 */
	open_queue_file(od, O_RDWR);

	/*
	 *  push relay
	 */
	for (r = qr->relay ; r; r = r->next)
		if (QUE_queue_add(QUE_UPDATE_RELAY, r, vni) != QUE_OK)
			alert_exit("queue space is empty");

	/*
	 *  push backup
	 */
	if (QUE_queue_add(QUE_UPDATE_RELAY, NULL, vni) != QUE_OK)
		alert_exit("queue space is empty");

	/*
	 *  close queue
	 */
	close_queue_file(od);

	/*
	 *  clean up
	 */
	free_qrelay(od, qr);
}

void
pull_qrelay(OD *od, QRELAY *qr, vxid_t vni)
{
	ADDR *r;

	/*
	 *  check queue sync enable
	 */
	if (qr == NULL)
		return;

	/*
	 *  open queue
	 */
	open_queue_file(od, O_RDWR);

	/*
	 *  pull relay
	 */
	for (r = qr->relay ; r; r = r->next)
		QUE_queue_delete(QUE_UPDATE_RELAY, r, vni);

	/*
	 *  close queue
	 */
	close_queue_file(od);

	/*
	 *  clean up
	 */
	free_qrelay(od, qr);
}

void
free_qrelay(OD *od, QRELAY *qr)
{
	ADDR *r;
	ADDR *n;

	if (qr == NULL)
		return;

	for (r = qr->relay; r; r = n) {
		n = r->next;
		free(r);
	}

	free(qr);
}

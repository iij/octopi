/*
 *  lpm.h  :  longest prefix match
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _LPM_H
#define _LPM_H

#include <stdint.h>

#include "addrutil.h"
#include "io_buffer.h"
#include "proto.h"

typedef uint32_t npos_t;

#define LPM_RELAY_Drop      ((ip4_t) 0)         /* 0.0.0.0 */
#define LPM_RELAY_Broadcast ((ip4_t) -1)        /* 255.255.255.255 */

#define LPM_ACL_Deny    LPM_RELAY_Drop
#define LPM_ACL_Accept  LPM_RELAY_Broadcast

#ifndef MIN_VNI
#define MIN_VNI                 (0)
#endif

#ifndef MAX_VNI
#define MAX_VNI                 (16777215)
#endif

enum {
	LPM_OK            = 0,
	LPM_FAIL          = 1,
};

/* open/close functions */
void LPM_lock_rules(void);
void LPM_unlock_rules(void);
void LPM_sync_rules(void);
void LPM_init_rules(char*, uint32_t, uint32_t);
void LPM_open_rules(char*, int);
void LPM_close_rules(void);
void LPM_open_or_init_rules(char*, int, uint32_t, uint32_t);
void LPM_reinit_rules(char*, uint32_t, uint32_t);

/* rule functions */
void LPM_unset_access_node(npos_t);
int LPM_get_next_relay(npos_t*, ADDR*);
int LPM_add_rule(uint32_t, npos_t);
void LPM_delete_rule(uint32_t, npos_t);
int LPM_move_rule(uint32_t, npos_t);
void LPM_flush_rule(uint32_t, uint8_t);
void LPM_update_rule(uint32_t, uint32_t, uint8_t);
void LPM_restore_start(uint8_t);
void LPM_restore_finish(uint8_t);
void LPM_restore_abort(uint8_t);
void LPM_fsck_rule(int);

/* misc functions */
void LPM_pause(int);
int  LPM_check_pause(void);
void LPM_queue_sync(int);
int  LPM_check_queue_sync(void);
uint8_t LPM_get_proto(npos_t);

/* IPv4 rule functions */
npos_t LPM_find_urelay_ip4(vxid_t, ip4_t);
npos_t LPM_find_mrelay_ip4(vxid_t);
int LPM_add_rule_ip4(vxid_t, npos_t);
void LPM_delete_rule_ip4(vxid_t, npos_t);
int LPM_move_rule_ip4(vxid_t, npos_t);
void LPM_flush_rule_ip4(vxid_t);
void LPM_update_rule_ip4(uint32_t, uint32_t);
npos_t LPM_set_access_node_ip4(ip4_t, uint8_t);
int LPM_set_access_relay_ip4(npos_t, ip4_t);

/* IPv6 rule functions */
npos_t LPM_find_urelay_ip6(vxid_t, ip6_t);
npos_t LPM_find_mrelay_ip6(vxid_t);
int LPM_add_rule_ip6(vxid_t, npos_t);
void LPM_delete_rule_ip6(vxid_t, npos_t);
int LPM_move_rule_ip6(vxid_t, npos_t);
void LPM_flush_rule_ip6(vxid_t);
void LPM_update_rule_ip6(uint32_t, uint32_t);
npos_t LPM_set_access_node_ip6(ip6_t, uint8_t);
int LPM_set_access_relay_ip6(npos_t, ip6_t);

/* display functions */
uint32_t LPM_listup_roots(uint8_t, uint64_t**, ADDR *);
void LPM_free_roots(uint64_t*);
void LPM_disp_target(IOBUF *buf, npos_t);
void LPM_disp_relay(IOBUF *buf, npos_t);
void LPM_disp_vni(IOBUF *, char *, vxid_t);
void LPM_show(IOBUF *buf, uint32_t, uint8_t);
void LPM_list(IOBUF *buf, char *, uint32_t, uint8_t);
int LPM_save_root(IOBUF *buf, int, uint32_t, uint8_t);
void LPM_save(IOBUF *buf, uint32_t, uint8_t);
void LPM_list_acl(IOBUF *buf, char *, uint8_t);

/* dump functions */
void LPM_dump_header(IOBUF *);
void LPM_count_node(IOBUF *);
void LPM_dump_all(IOBUF *);

#endif /* _LPM_H */

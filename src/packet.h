/*
 *  packet.h
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#pragma once
#pragma pack(1)
#ifndef _PACKET_H
#define _PACKET_H

#include <stdint.h>
#include <syslog.h>
#include "addrutil.h"

#ifndef ETHER_ADDR_LEN
#  define ETHER_ADDR_LEN        (6)
#endif

#ifndef IP4_ADDR_LEN
#  define IP4_ADDR_LEN          (4)
#endif

#ifndef IP6_ADDR_LEN
#  define IP6_ADDR_LEN          (16)
#endif

#ifndef ICMP6_NA_SOLICITED
#  define ICMP6_NA_SOLICITED    (0x40)
#endif

#ifndef VXLAN_FLAG
#  define VXLAN_FLAG            (0x8)
#endif

typedef struct payload {
	uint8_t outer_af;
	uint8_t inner_af;
	union {
		uint32_t  relay_ip4;
		uint128_t relay_ip6;
	};
	union {
		uint32_t  src_ip4;
		uint128_t src_ip6;
	};
	union {
		uint32_t  dst_ip4;
		uint128_t dst_ip6;
	};
	uint32_t  site_begin;
	uint32_t  site_end;
	uint32_t  vni;
	uint8_t   *data;
	uint32_t  data_len;
	uint8_t   *buf;
	uint32_t  buf_len;
} PAYLOAD;

typedef struct octopi_packet {
	/*
	 *  octopi header
	 */
	uint8_t  octopi_magic;
	uint8_t  octopi_proto;
	uint16_t random;
	uint8_t  secret[16];
	uint32_t time_sec;
	uint16_t time_msec;
	uint32_t site_begin;
	uint32_t site_end;
} __attribute__((__packed__)) PACKET;

typedef struct octopi_address_ip4 {
	uint32_t src_ip4;
	uint32_t dst_ip4;
} __attribute__((__packed__)) ADDRESS4;

typedef struct octopi_address_ip6 {
	uint128_t src_ip6;
	uint128_t dst_ip6;
} __attribute__((__packed__)) ADDRESS6;

struct ether_packet {
	union {
		struct {
			uint8_t dst_mac[ETHER_ADDR_LEN];
			uint8_t src_mac[ETHER_ADDR_LEN];
		} __attribute__((__packed__));
		struct {
			uint32_t site_flag;
			uint32_t site_begin;
			uint32_t site_end;
		} __attribute__((__packed__));
	};
	uint16_t ether_type;
} __attribute__((__packed__));

struct arp_packet {
	uint16_t ha_type;
	uint16_t pa_type;
	uint8_t  ha_len;
	uint8_t  pa_len;
	uint16_t operation;
	uint8_t  sender_ha[ETHER_ADDR_LEN];
	uint32_t sender_pa;
	uint8_t  target_ha[ETHER_ADDR_LEN];
	uint32_t target_pa;
} __attribute__((__packed__));

struct ip_packet {
	uint8_t  version;
	uint8_t  tos;
	uint16_t len;
	uint16_t id;
	uint16_t flags;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t checksum;
	uint32_t src_ip4;
	uint32_t dst_ip4;
} __attribute__((__packed__)) ;

struct ip6_packet {
	uint8_t   version;
	uint8_t   tos;
	uint16_t  label;
	uint16_t  len;
	uint8_t   proto;
	uint8_t   ttl;
	uint128_t src_ip6;
	uint128_t dst_ip6;
} __attribute__((__packed__));

struct udp_vxlan {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t  vxlan_flags;
	uint8_t  reserved[3];
	uint32_t vni;
} __attribute__((__packed__));

struct icmp6_packet {
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint8_t   flags;
	uint8_t   reserved[3];
	uint128_t target;
} __attribute__((__packed__));

typedef struct cast_ip4 {
	struct ether_packet ether;
	struct ip_packet    ip;
} __attribute__((__packed__)) CAST4;

typedef struct cast_ip6 {
	struct ether_packet ether;
	struct ip6_packet   ip6;
} __attribute__((__packed__)) CAST6;

#endif /* _PACKET_H */

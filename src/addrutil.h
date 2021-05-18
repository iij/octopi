/*
 *  addrutil.h
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _ADDRUTIL_H
#define _ADDRUTIL_H

#include <stdint.h>
#include <arpa/inet.h>

#ifdef __SIZEOF_INT128__
#ifndef UINT128_MAX
typedef __uint128_t uint128_t;
#endif
#else
#error "This program needs uint128_t."
#endif

#ifndef INET6_ADDRSTRLEN
#  define INET6_ADDRSTRLEN      (46)
#endif

#define IP_STR_LEN   (INET6_ADDRSTRLEN)
#define CIDR_STR_LEN (INET6_ADDRSTRLEN + 4)

typedef uint32_t ip4_t;
typedef uint128_t ip6_t;
typedef uint32_t vxid_t;

struct addrutil;
typedef struct addrutil {
        int af;
	int mask;
	struct addrutil *next;
        union {
		ip4_t     ipv4_addr;
		ip6_t     ipv6_addr;
                uint8_t   addr[16];
                uint16_t  addr16[8];
                uint32_t  addr32[4];
                uint64_t  addr64[2];
        };
} ADDR;

extern ip4_t v4mask[];
extern ip6_t v6mask[];

void init_netmasks(void);
int check_cidr_ipv4(ip4_t, ADDR*);
int check_cidr_ipv6(ip6_t, ADDR*);

ip6_t ntohq(ip6_t);
static inline ip6_t htonq(ip6_t src) { return ntohq(src); }
int str_to_uint32(char*, uint32_t*);
int str_to_uint64(char*, uint64_t*);
int str_to_ip4(char*, ip4_t*);
int ip4_to_str(ip4_t*, char*);
int str_to_ip6(char*, ip6_t*);
int ip6_to_str(ip6_t*, char*);
int str_to_addr(char*, ADDR*);
int addr_to_str(ADDR*, char*);
int str_to_cidr(char*, ADDR*);
int cidr_to_str(ADDR*, char*);
int addr_match(ADDR*, ADDR *);

#endif /* _ADDRUTIL_H */

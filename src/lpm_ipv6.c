/*
 *  lpm_ipv6.c
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#include <stdint.h>

#include "lpm.h"
#include "addrutil.h"

#define IP_t            ip6_t
#define IPsize          (128)
#define IPmask          v6mask
#define IP_ADDR         ipv6_addr
#define IP_FUNC(name)   name ## _ip6
#define IP_PROTO        PROTO_IP6
#define IP_WILD_CARD    (1)

static inline uint8_t
diff_addr(ip6_t addr1, ip6_t addr2)
{
	ip6_t addr = addr1 ^ addr2;
	uint64_t a;

	if (addr == 0)
		return 0;

	a = addr >> 64;
	if (a)
		return __builtin_clzll(a) + 1;

	return __builtin_clzll(addr & 0xffffffffffffffffUL) + 65;
}

#include "lpm_common.c"

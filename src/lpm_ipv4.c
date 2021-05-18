/*
 *  lpm_ipv4.c
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#include <stdint.h>

#include "lpm.h"
#include "addrutil.h"

#define IP_t            ip4_t
#define IPsize          (32)
#define IPmask          v4mask
#define IP_ADDR         ipv4_addr
#define IP_FUNC(name)   name ## _ip4
#define IP_PROTO        PROTO_IP4
#define IP_WILD_CARD    (0)

static inline uint8_t
diff_addr(ip4_t addr1, ip4_t addr2)
{
	ip4_t addr = addr1 ^ addr2;
	if (addr == 0)
		return 0;

	return __builtin_clz(addr) + 1;
}

#include "lpm_common.c"

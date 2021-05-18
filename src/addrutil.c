/*
 *  addrutil.c
 *
 *  copyright (c) 2010-2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "addrutil.h"

enum {
	FALSE = 0,
	TRUE  = 1,
};

/*
 *  global netmasks
 */
ip4_t v4mask[32+1];
ip6_t v6mask[128+1];

/*
 *  initialize netmasks
 */
void
init_netmasks()
{
	ip4_t n = 1;
	ip6_t nn = 1;
        int i;

        for (i = 32; i > 0; --i)
                v4mask[i] = ~((n << (32 - i)) -1);
	v4mask[0] = 0;

	for (i = 128; i > 0; --i)
		v6mask[i] = ~((nn << (128 - i)) - 1);
	v6mask[0] = 0;
}

/*
 *  128 bit ntoh and hton
 */
ip6_t
ntohq(ip6_t src)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	return src;
#else
	union {
		ip6_t     ipv6_addr;
		uint32_t  addr32[4];
	} a, b;

	a.ipv6_addr = src;
	b.addr32[0] = ntohl(a.addr32[3]);
	b.addr32[1] = ntohl(a.addr32[2]);
	b.addr32[2] = ntohl(a.addr32[1]);
	b.addr32[3] = ntohl(a.addr32[0]);

	return b.ipv6_addr;
#endif
}

/*
 *  check address in CIDR
 */
int
check_cidr_ipv4(ip4_t src, ADDR *addr)
{
	ADDR *a;

	for (a = addr; a; a = a->next) {
		ip4_t mask = v4mask[a->mask];

		if (a->af != AF_INET)
			continue;
		if ((a->ipv4_addr & mask) == (src & mask))
			return TRUE;
	}

	return FALSE;
}

int
check_cidr_ipv6(ip6_t src, ADDR *addr)
{
	ADDR *a;

	for (a = addr; a; a = a->next) {
		ip6_t mask = v6mask[a->mask];
		if (a->af != AF_INET6)
			continue;
		if ((a->ipv6_addr & mask) == (src & mask))
			return TRUE;
	}

	return FALSE;
}

/*
 *  convert string to number
 */
int
str_to_uint32(char *src, uint32_t *dst)
{
	char *endp;
	uint32_t val;

	if (src == NULL)
		return FALSE;
	if (*src == 0)
		return FALSE;

	val = strtoul(src, &endp, 0);
	if (*endp != 0)
		return FALSE;

	*dst = val;
	return TRUE;
}

int
str_to_uint64(char *src, uint64_t *dst)
{
	char *endp;
	uint64_t val;

	if (src == NULL)
		return FALSE;
	if (*src == 0)
		return FALSE;

	val = strtoull(src, &endp, 0);
	if (*endp != 0)
		return FALSE;

	*dst = val;
	return TRUE;
}

/*
 *  convert string and IP address
 */
int
str_to_ip4(char *src, ip4_t *dst)
{
	struct in_addr a;

	if (src == NULL)
		return FALSE;

	if (inet_aton(src, &a) == 0)
		return FALSE;

	*dst = ntohl(a.s_addr);
	return TRUE;
}

int
ip4_to_str(ip4_t *src, char *dst)
{
	ip4_t n;
	const char *p;

	if (src == NULL)
		return FALSE;

	n = htonl(*src);
	p = inet_ntop(AF_INET, &n, dst, INET_ADDRSTRLEN);
	if (p == NULL)
		return FALSE;

	return TRUE;
}

int
str_to_ip6(char *src, ip6_t *dst)
{
	struct in6_addr a;

	if (src == NULL)
		return FALSE;

	if (inet_pton(AF_INET6, src, &a) == 0) {
		return FALSE;
	}

	*dst = ntohq(*(ip6_t *)(&a));
	return TRUE;
}

int
ip6_to_str(ip6_t *src, char *dst)
{
	ip6_t n;
	const char *p;

	if (src == NULL)
		return FALSE;

	n = htonq(*src);
	p = inet_ntop(AF_INET6, &n, dst, IP_STR_LEN);
	if (p == NULL)
		return FALSE;

	return TRUE;
}

int
str_to_addr(char *src, ADDR *dst)
{
	if (src == NULL)
		return FALSE;

	if (strchr(src, ':') != NULL) {
		if (str_to_ip6(src, &dst->ipv6_addr) == FALSE)
			return FALSE;
		dst->af = AF_INET6;
	} else {
		if (str_to_ip4(src, &dst->ipv4_addr) == FALSE)
			return FALSE;
		dst->af = AF_INET;
	}
	dst->mask = 0;
	dst->next = NULL;

	return TRUE;
}

int
addr_to_str(ADDR *src, char *dst)
{
	if (src == NULL)
		return FALSE;

	if (src->af == AF_INET) {
		return ip4_to_str(&src->ipv4_addr, dst);
	} else if (src->af == AF_INET6) {
		return ip6_to_str(&src->ipv6_addr, dst);
	}

	return FALSE;
}

/*
 *  convert string and CIDR
 */
int
str_to_cidr(char *src, ADDR *dst)
{
	char buf[IP_STR_LEN];
	char *mp;
	uint32_t mask;

	if (src == NULL)
		return FALSE;

	mp = strchr(src, '/');
	if (mp == NULL) {
		/*
		 *  no mask specified
		 */
		if (str_to_addr(src, dst) == FALSE)
			return FALSE;

		if (dst->af == AF_INET) {
			dst->mask = 32;
		} else if (dst->af == AF_INET6) {
			dst->mask = 128;
		} else {
			return FALSE;
		}
		return  TRUE;
	}

	/*
	 *  convert address
	 */
	if (mp - src + 1 > IP_STR_LEN)
		return FALSE;
	memcpy(buf, src, mp - src);
	buf[mp - src] = 0;
	if (str_to_addr(buf, dst) == FALSE)
		return FALSE;

	/*
	 *  convert mask
	 */
	mp ++;
	if (str_to_uint32(mp, &mask) == FALSE)
		return FALSE;
	if (dst->af == AF_INET && mask > 32)
		return FALSE;
	if (dst->af == AF_INET6 && mask > 128)
		return FALSE;
	dst->mask = (int) mask;

	return TRUE;
}

int
cidr_to_str(ADDR *src, char *dst)
{
	char buf[IP_STR_LEN];

	if (addr_to_str(src, buf) == FALSE)
		return FALSE;

	snprintf(dst, CIDR_STR_LEN, "%s/%d", buf, src->mask);
	return TRUE;
}

int
addr_match(ADDR* a, ADDR *b)
{
	if (a->af == AF_INET && b->af == AF_INET)
		return (a->ipv4_addr == b->ipv4_addr);

	if (a->af == AF_INET6 && b->af == AF_INET6)
		return (a->ipv6_addr == b->ipv6_addr);

	return 0;
}

/*
 *  command_find.c
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "octopi.h"
#include "addrutil.h"
#include "logging.h"
#include "command.h"
#include "lpm.h"
#include "rule.h"

static const char* const subcmd = "find";

static void
command_usage(int status)
{
	info("usage: %s [rule] %s vni [address]", COMMAND_NAME, subcmd);
	info("\tvni      := number (%u ... %u)", MIN_VNI, MAX_VNI);
	info("\taddress  := \"ipv4\" | \"ipv6\" | address (overlay)");
	exit(status);
};

static npos_t
find_mrelay(uint32_t vni, uint8_t proto)
{
	npos_t node = 0;

	if (proto == PROTO_IP4)
		node = LPM_find_mrelay_ip4(vni);
	else
		node = LPM_find_mrelay_ip6(vni);

	return node;
}

static npos_t
find_urelay(uint32_t vni, ADDR *a)
{
	npos_t node = 0;

	if (a->af == AF_INET)
		node = LPM_find_urelay_ip4(vni, a->ipv4_addr);
	else if (a->af == AF_INET6)
		node = LPM_find_urelay_ip6(vni, a->ipv6_addr);

	return node;
}

void
command_find(OD *od, int ac, char *av[])
{
	uint32_t vni;
	uint8_t proto = PROTO_NONE;
	ADDR addr;
	npos_t node;
	char *errmsg;

	/* check help */
	if (ac > 0)
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

	/* check arguments */
	if (ac < 1) {
		error("%s: insufficient arguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* vni */
	if (conv_vni(av[0], &vni, &errmsg) == FALSE) {
		error("%s: %s", subcmd, errmsg);
		command_usage(EXIT_FAILURE);
	}
	if (vni == VNI_ALL) {
		error("%s: vni must be a number or \"any\"", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* address */
	if (ac > 1) {
		if (strcasecmp(av[1], "ipv4") == 0) {
			proto = PROTO_IP4;
		} else if (strcasecmp(av[1], "ipv6") == 0) {
			proto = PROTO_IP6;
		} else {
			if (str_to_addr(av[1], &addr) == FALSE) {
				error("%s: invalid address", subcmd);
				command_usage(EXIT_FAILURE);
			}
		}
	} else {
		proto = PROTO_IP4;
	}

	/* check garbage */
	if (ac > 2) {
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  find
	 */
	open_rule_file(od, O_RDONLY);
	if (proto == PROTO_IP4 || proto == PROTO_IP6)
		node = find_mrelay(vni, proto);
	else
		node = find_urelay(vni, &addr);

	zprintf(NULL, "relay");
	if (node)
		LPM_disp_relay(NULL, node);
	else
		zprintf(NULL, " none\n");

	close_rule_file(od);
}

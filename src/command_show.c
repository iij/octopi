/*
 *  command_show.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
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

static const char* const subcmd = "show";

static void
command_usage(int status)
{
	info("usage: %s [rule] %s [vni [protocol]]", COMMAND_NAME, subcmd);
	info("\tvni      := \"all\" | number (%u ... %u) | \"any\"",
	     MIN_VNI, MAX_VNI);
	info("\tprotocol := \"all\" | \"ipv4\" | \"ipv6\"");
	exit(status);
};

static void
show_vni(OD *od, uint32_t vni, uint8_t proto)
{
	open_rule_file(od, O_RDONLY);
	LPM_show(NULL, vni, proto);
	close_rule_file(od);
}

static void
show_all(OD *od, uint8_t proto)
{
	uint32_t count;
	uint64_t *list;
	uint32_t n;
	uint32_t prev_vni = VNI_INVALID;

	open_rule_file(od, O_RDONLY);
	count = LPM_listup_roots(proto, &list, NULL);

	for (n = 0; n < count; ++ n) {
		uint32_t vni = list[n] >> 8;
		if (vni != prev_vni) {
			LPM_show(NULL, vni, proto);
			prev_vni = vni;
		}
	}

	LPM_free_roots(list);
	close_rule_file(od);
}

void
command_show(OD *od, int ac, char *av[])
{
	uint32_t vni = VNI_ALL;
	uint8_t proto = PROTO_ALL;
	char *errmsg;

	if (ac > 0) {
		/* check help */
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

		/* vni */
		if (conv_vni(av[0], &vni, &errmsg) == FALSE) {
			error("%s: %s", subcmd, errmsg);
			command_usage(EXIT_FAILURE);
		}
	}

	/* protocol */
	if (ac > 1) {
		if (conv_proto(av[1], &proto, &errmsg) == FALSE) {
			error("%s: %s", subcmd, errmsg);
			command_usage(EXIT_FAILURE);
		}
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
	 *  show
	 */
	if (vni == VNI_ALL)
		show_all(od, proto);
	else
		show_vni(od, vni, proto);
}

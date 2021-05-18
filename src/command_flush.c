/*
 *  command_flush.c
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
#include "rule.h"
#include "lpm.h"

static const char* const subcmd = "flush";

static void
command_usage(int status)
{
	info("usage: %s [rule] %s vni [protocol]", COMMAND_NAME, subcmd);
	info("\tvni      := \"all\" | number (%u ... %u) | \"any\"",
	     MIN_VNI, MAX_VNI);
	info("\tprotocol := \"all\" | \"ipv4\" | \"ipv6\"");
	exit(status);
};

static void
flush_vni(OD *od, vxid_t vni, uint8_t proto)
{
	QRELAY *qr;

	/* open rule */
	open_rule_file(od, O_RDWR);

	/* get previous relay */
	qr = init_qrelay(od);
	get_qrelay(od, qr, vni);

	/* flush rules */
	LPM_flush_rule(vni, proto);

	/* queue sync */
	push_qrelay(od, qr, vni);

	/* close rule */
	sync_rule_file(od);
	close_rule_file(od);
}

static void
flush_all(OD *od, uint8_t proto)
{
	uint32_t count;
	uint64_t *list;
	uint32_t n;
	QRELAY *qr;

	/* open rule */
	open_rule_file(od, O_RDWR);

	/* initialize relay */
	qr = init_qrelay(od);

	/* loop all vni */
	count = LPM_listup_roots(proto, &list, NULL);
	for (n = 0; n < count; ++ n) {
		uint32_t vni = list[n] >> 8;
		int p = list[n] & 0xff;

		get_qrelay(od, qr, vni);
		LPM_flush_rule(vni, p);
	}
	LPM_free_roots(list);

	/* queue sync */
	push_qrelay(od, qr, VNI_ALL);

	/* close rule */
	sync_rule_file(od);
	close_rule_file(od);
}

void
command_flush(OD *od, int ac, char *av[])
{
	uint32_t vni;
	uint8_t proto = PROTO_ALL;
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
	 *  flush
	 */
	if (vni == VNI_ALL)
		flush_all(od, proto);
	else
		flush_vni(od, vni, proto);
}

/*
 *  command_add.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
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

static const char* const subcmd = "add";

static void
command_usage(int status)
{
	info("usage: %s [rule] %s vni target relay [relay ...]",
	       COMMAND_NAME, subcmd);
	info("\tvni      := number (%u ... %u) | \"any\"", MIN_VNI, MAX_VNI);
	info("\ttarget   := address[/mask] (overlay)");
	info("\trelay    := octopid address (underlay)");
	exit(status);
};

void
command_add(OD *od, int ac, char *av[])
{
	uint32_t vni;
	npos_t node;
	char *errmsg;
	QRELAY *qr;

	/* check help */
	if (ac > 0)
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

	/* check arguments */
	if (ac < 3) {
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

	/* open rule */
	open_rule_file(od, O_RDWR);

	/* target */
	if (conv_target(av[1], &node, od->dryrun, &errmsg) == FALSE) {
		close_rule_file(od);
		error("%s: %s", subcmd, errmsg);
		command_usage(EXIT_FAILURE);
	}

	/* relay */
	if (conv_relays(node, ac - 2, av + 2, od->dryrun, &errmsg) == FALSE) {
		close_rule_file(od);
		error("%s: %s", subcmd, errmsg);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  add
	 */
	if (LPM_add_rule(vni, node) != LPM_OK)
		alert_exit("rule space is empty");

	/* queue sync */
	qr = init_qrelay(od);
	get_qrelay(od, qr, vni);
	push_qrelay(od, qr, vni);

	/* close rule */
	sync_rule_file(od);
	close_rule_file(od);
}

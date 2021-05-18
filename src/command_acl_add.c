/*
 *  command_acl_add.c
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

static const char* const subcmd = "acl";
static const char* const optcmd = "add";

static void
command_usage(int status)
{
	info("usage: %s %s %s target action", COMMAND_NAME, subcmd, optcmd);
	info("\ttarget   := address[/mask]");
	info("\taction   := \"allow\" | \"deny\"");
	exit(status);
};

void
command_acl_add(OD *od, int ac, char *av[])
{
	npos_t node;
	char *errmsg;

	/* check help */
	if (ac > 0)
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

	/* check arguments */
	if (ac < 2) {
		error("%s: insufficient arguments", subcmd);
		command_usage(EXIT_FAILURE);
	}
	if (ac > 2) {
                error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* open rule */
	open_rule_file(od, O_RDWR);

	/* target */
	if (conv_target(av[0], &node, od->dryrun, &errmsg) == FALSE) {
		close_rule_file(od);
		error("%s: %s", subcmd, errmsg);
		command_usage(EXIT_FAILURE);
	}

	/* acl */
	if (conv_acl(node, av[1], od->dryrun, &errmsg) == FALSE) {
		close_rule_file(od);
		error("%s: %s", subcmd, errmsg);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  add or replace acl
	 */
	LPM_move_rule(VNI_ACL, node);

	/* close rule */
	sync_rule_file(od);
	close_rule_file(od);
}

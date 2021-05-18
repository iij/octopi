/*
 *  command_acl_delete.c
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
static const char* const optcmd = "delete";

static void
command_usage(int status)
{
	info("usage: %s %s %s target", COMMAND_NAME, subcmd, optcmd);
	info("\ttarget   := \"all\" | address[/mask]");
	exit(status);
};

void
command_acl_delete(OD *od, int ac, char *av[])
{
	npos_t node;
	char *errmsg;
	int all = 0;

	/* check help */
	if (ac > 0)
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

	/* check arguments */
	if (ac < 1) {
		error("%s: insufficient arguments", subcmd);
		command_usage(EXIT_FAILURE);
	}
	if (ac > 1) {
                error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* open rule */
	open_rule_file(od, O_RDWR);

	/* target */
	if (strcasecmp(av[0], "all") == 0) {
		all = 1;
	} else if (conv_target(av[0], &node, od->dryrun, &errmsg) == FALSE) {
		close_rule_file(od);
		error("%s: %s", subcmd, errmsg);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  delete acl
	 */
	if (all)
		LPM_flush_rule(VNI_ACL, PROTO_ALL);
	else
		LPM_delete_rule(VNI_ACL, node);

	/* close rule */
	sync_rule_file(od);
	close_rule_file(od);
}

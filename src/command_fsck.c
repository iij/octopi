/*
 *  command_fsck.c
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

static const char* const subcmd = "fsck";

static void
command_usage(int status)
{
	info("usage: %s [rule] %s [\"normal\" | \"all\"]",
	     COMMAND_NAME, subcmd);
	exit(status);
};

void
command_fsck(OD *od, int ac, char *av[])
{
	int all = 0;

	if (ac > 0) {
		/* check help */
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

		/* type */
		if (strcasecmp(av[0], "normal") == 0)
			all = 0;
		else if (strcasecmp(av[0], "all") == 0)
			all = 1;
		else
			command_usage(EXIT_FAILURE);
	}

	/* check garbage */
	if (ac > 1) {
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  fsck
	 */
	open_rule_file(od, O_RDWR);
	LPM_flush_rule(VNI_WORK, PROTO_ALL);
	LPM_fsck_rule(all);

	sync_rule_file(od);
	close_rule_file(od);
}

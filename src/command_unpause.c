/*
 *  command_unpause.c
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

static const char* const subcmd = "unpause";

static void
command_usage(int status)
{
	info("usage: %s [rule] %s", COMMAND_NAME, subcmd);
	exit(status);
};

void
command_unpause(OD *od, int ac, char *av[])
{
	if (ac > 0) {
		/* check help */
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

		/* check garbage */
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  uppause
	 */
	open_rule_file(od, O_RDWR);
	LPM_pause(0);
	sync_rule_file(od);
	close_rule_file(od);
}

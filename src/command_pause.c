/*
 *  command_pause.c
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

static const char* const subcmd = "pause";

static void
command_usage(int status)
{
	info("usage: %s [rule] %s", COMMAND_NAME, subcmd);
	exit(status);
};

void
command_pause(OD *od, int ac, char *av[])
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
	 *  pause
	 */
	open_rule_file(od, O_RDWR);
	LPM_pause(1);
	sync_rule_file(od);
	close_rule_file(od);
}

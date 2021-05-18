/*
 *  command_queue_disable.c
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
#include "rule.h"

static const char* const subcmd = "queue";
static const char* const optcmd = "disable";

static void
command_usage(int status)
{
	info("usage: %s %s %s", COMMAND_NAME, subcmd, optcmd);
	exit(status);
};

void
command_queue_disable(OD *od, int ac, char *av[])
{
	/* check help */
	if (ac >= 1 && strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	/* check auguments */
	if (ac > 0) {
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_SUCCESS);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  sync enable
	 */
	open_rule_file(od, O_RDWR);
	LPM_queue_sync(0);
	sync_rule_file(od);
	close_rule_file(od);
}

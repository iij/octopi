/*
 *  command_queue_dump.c
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
#include "que.h"
#include "rule.h"

static const char* const subcmd = "queue";
static const char* const optcmd = "dump";

static void
command_usage(int status)
{
	info("usage: %s %s %s [\"header\" | \"all\"]",
	     COMMAND_NAME, subcmd, optcmd);
	exit(status);
};

void
command_queue_dump(OD *od, int ac, char *av[])
{
	int all = 0;

	if (ac > 0) {
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);
		else if (strcasecmp(av[0], "header") == 0)
			all = 0;
		else if (strcasecmp(av[0], "all") == 0)
			all = 1;
		else
			command_usage(EXIT_FAILURE);
	}
	if (ac > 1) {
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	if (od->dryrun)
		return;

	/* open queue */
	open_queue_file(od, O_RDONLY);
	QUE_dump_header(NULL);
	QUE_count_node(NULL);

	if (all)
		QUE_dump_all(NULL);

	/* close queue */
	close_queue_file(od);
}

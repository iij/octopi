/*
 *  command_dump.c
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

static const char* const subcmd = "dump";

static void
command_usage(int status)
{
	info("usage: %s %s [\"header\" | \"all\"]", COMMAND_NAME, subcmd);
	exit(status);
};

void
command_dump(OD *od, int ac, char *av[])
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

	open_rule_file(od, O_RDONLY);
	LPM_dump_header(NULL);
	LPM_count_node(NULL);
	if (all)
		LPM_dump_all(NULL);
	close_rule_file(od);
}

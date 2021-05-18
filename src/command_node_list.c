/*
 *  command_node_list.c
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

static const char* const subcmd = "node";
static const char* const optcmd = "list";

static void
command_usage(int status)
{
	info("usage: %s %s %s [relay ...]", COMMAND_NAME, subcmd, optcmd);
	info("\trelay    := address");
	exit(status);
};

void
command_node_list(OD *od, int ac, char *av[])
{
	ADDR relay;
	int i;

	/* check help */
	if (ac >= 1 && strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	/* check auguments */
	if (ac > 0) {
		for (i = 0; i < ac; ++ i) {
			if (str_to_addr(av[i], &relay) == FALSE) {
				error("%s: relay must be IPv4/IPv6 address",
				      subcmd);
				command_usage(EXIT_SUCCESS);
			}
		}
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/* open queue */
	open_queue_file(od, O_RDONLY);

	/* list */
	if (ac <= 0) {
		QUE_node_list(NULL, COMMAND_NAME, NULL);
	} else {
		for (i = 0; i < ac; ++ i) {
			str_to_addr(av[i], &relay);
			QUE_node_list(NULL, COMMAND_NAME, &relay);
		}
	}

	/* close queue */
	close_queue_file(od);
}

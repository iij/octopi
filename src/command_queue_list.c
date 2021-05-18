/*
 *  command_queue_list.c
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
static const char* const optcmd = "list";

static void
command_usage(int status)
{
	info("usage: %s %s %s [relay ...]", COMMAND_NAME, subcmd, optcmd);
	info("\trelay    := address");
	exit(status);
};

static void
queue_list(OD *od, int ac, char *av[])
{
	ADDR relay;
	int i;

	for (i = 0; i < ac; ++ i) {
		if (strcasecmp(av[i], "backup") == 0) {
			QUE_queue_list(NULL, NULL);
		} else {
			if (str_to_addr(av[i], &relay) == FALSE) {
				error("%s: relay must be IPv4/IPv6 address",
				      subcmd);
				command_usage(EXIT_SUCCESS);
			}
			QUE_queue_list(NULL, &relay);
		}
	}
}

void
command_queue_list(OD *od, int ac, char *av[])
{
	/* check help */
	if (ac >= 1 && strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	/* check dryrun */
	if (od->dryrun)
		return;

	/* open queue */
	open_queue_file(od, O_RDONLY);

	if (ac <= 0) {
		/* all list */
		QUE_queue_list_all(NULL);
	} else {
		/* list */
		queue_list(od, ac, av);
	}

	close_queue_file(od);
}

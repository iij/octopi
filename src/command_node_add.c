/*
 *  command_node_add.c
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
static const char* const optcmd = "add";

static void
command_usage(int status)
{
	info("usage: %s %s %s relay [member ...]",
	     COMMAND_NAME, subcmd, optcmd);
	info("\trelay    := address");
	info("\tnode     := real node address");
	exit(status);
};

void
command_node_add(OD *od, int ac, char *av[])
{
	ADDR relay;
	ADDR member;
	int i;

	/* check auguments */
	if (ac <= 0)
		command_usage(EXIT_FAILURE);

	/* check help */
	if (strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	/* check relay */
	if (str_to_addr(av[0], &relay) == FALSE) {
		error("%s: relay must be IPv4/IPv6 address", subcmd);
		command_usage(EXIT_SUCCESS);
	}

	/* check member */
	for (i = 1; i < ac; ++ i) {
		if (str_to_addr(av[i], &member) == FALSE) {
			error("%s: member must be IPv4/IPv6 address", subcmd);
			command_usage(EXIT_SUCCESS);
		}
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/* open queue */
	open_queue_file(od, O_RDWR);

	/*
	 *  add
	 */
	if (ac == 1) {
		if (QUE_node_add(&relay, &relay) != QUE_OK) {
			error_exit("%s: out of queue\n", subcmd);
		}
	} else {
		for (i = 1; i < ac; ++ i) {
			str_to_addr(av[i], &member);
			if (QUE_node_add(&relay, &member) != QUE_OK) {
				error_exit("%s: out of queue\n", subcmd);
			}
		}
	}

	/* close queue */
	close_queue_file(od);
}

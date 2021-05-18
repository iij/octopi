/*
 *  command_node.c
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

static const char* const subcmd = "node";

static void
command_usage(int status)
{
	info("usage: %s %s sub-command [arguments...]}", COMMAND_NAME, subcmd);
	info(" ");
        info("[sub-command]");
	info("\tlist, add, delete");
	exit(status);
};

void
command_node(OD *od, int ac, char *av[])
{
	if (ac <= 0)
		command_usage(EXIT_FAILURE);

	if (strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);
	else if (strcasecmp(av[0], "add") == 0)
		command_node_add(od, ac - 1, av + 1);
	else if (strcasecmp(av[0], "delete") == 0)
		command_node_delete(od, ac - 1, av + 1);
	else if (strcasecmp(av[0], "list") == 0)
		command_node_list(od, ac - 1, av + 1);
	else
		command_usage(EXIT_FAILURE);
}

/*
 *  command_backup_delete.c
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

static const char* const subcmd = "backup";
static const char* const optcmd = "delete";

static void
command_usage(int status)
{
	info("usage: %s %s %s [member ...]", COMMAND_NAME, subcmd, optcmd);
	info("\tmember   := backup member node address");
	exit(status);
}

void
command_backup_delete(OD *od, int ac, char *av[])
{
	ADDR node;
	int i;

	/* check help */
	if (ac >= 1 && strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	/* check node */
	for (i = 0; i < ac; ++ i) {
		if (str_to_addr(av[i], &node) == FALSE) {
			error("%s: node must be IPv4/IPv6 address", subcmd);
			command_usage(EXIT_SUCCESS);
		}
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/* open queue */
	open_queue_file(od, O_RDWR);

	/*
	 *  delete
	 */
	if (ac == 0) {
		QUE_backup_delete(NULL);
	} else {
		for (i = 0; i < ac; ++ i) {
			str_to_addr(av[i], &node);
			QUE_backup_delete(&node);
		}
	}

	/* close queue */
	close_queue_file(od);
}

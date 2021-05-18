/*
 *  command_acl_list.c
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
#include "lpm.h"
#include "rule.h"

static const char* const subcmd = "acl";
static const char* const optcmd = "list";

static void
command_usage(int status)
{
	info("usage: %s %s %s [protocol]", COMMAND_NAME, subcmd, optcmd);
	info("\tprotocol := \"all\" | \"ipv4\" | \"ipv6\"");
	exit(status);
}

void
command_acl_list(OD *od, int ac, char *av[])
{
	uint8_t proto = PROTO_ALL;
	char *errmsg;

	/* check help */
	if (ac > 0)
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

	/* protocol */
	if (ac > 0) {
		if (conv_proto(av[0], &proto, &errmsg) == FALSE) {
			error("%s: %s", subcmd, errmsg);
			command_usage(EXIT_FAILURE);
		}
	}

	/* check garbage */
	if (ac > 1) {
                error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/* open rule */
	open_rule_file(od, O_RDONLY);

	/*
	 *  list acl
	 */
	LPM_list_acl(NULL, COMMAND_NAME, proto);

	/* close rule */
	close_rule_file(od);
}

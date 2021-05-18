/*
 *  command_update.c
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

static const char* const subcmd = "update";

static void
command_usage(int status)
{
	info("usage: %s %s [protocol]", COMMAND_NAME, subcmd);
	info("\tprotocol := \"all\" | \"ipv4\" | \"ipv6\"");
	info(" ");
	info("rule vni");
	info("target relay [relay...]");
	info("commit | abort");
	info("\tvni      := number (%u ... %u) | \"any\"", MIN_VNI, MAX_VNI);
	info("\ttarget   := address[/mask] (overlay)");
	info("\trelay    := octopid address (underlay)");

	exit(status);
};

void
command_update(OD *od, int ac, char *av[])
{
	uint8_t proto = PROTO_ALL;
	char *errmsg;

	if (ac > 0) {
		/* check help */
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

		/* protocol */
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

	/*
	 *  update
	 */
	if (update_rules(od, STDIN_FILENO, proto, FALSE, NULL) == FALSE)
		exit(EXIT_FAILURE);
}

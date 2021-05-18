/*
 *  command_queue_delete.c
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
static const char* const optcmd = "delete";

static void
command_usage(int status)
{
	info("usage: %s %s %s [utype] node [vni]",
	     COMMAND_NAME, subcmd, optcmd);
	info("\tutype    := \"auto\" | \"relay\" | \"member\" | \"both\"");
	info("\tnode     := \"all\" | \"backup\" | address");
	info("\tvni      := \"all\" | number (%u ... %u) | \"any\"",
	     MIN_VNI, MAX_VNI);

	exit(status);
};

void
command_queue_delete(OD *od, int ac, char *av[])
{
	ADDR node;
	int utype = QUE_UPDATE_AUTO;
	ADDR *n = &node;
	int all_node = 0;
	uint32_t vni = VNI_ALL;
	char *errmsg;

	/* check arguments */
	if (ac < 1) {
		error("%s: insufficient arguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check help */
	if (strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	/* check update */
	if (conv_que_update(av[0], &utype) == QUE_OK) {
		av ++;
		ac --;
	}

	/* check node */
	if (strcasecmp(av[0], "all") == 0) {
		all_node = 1;
	} else if (utype == QUE_UPDATE_AUTO
		   && strcasecmp(av[0], "backup") == 0) {
		n = NULL;
	} else {
		if (str_to_addr(av[0], n) == FALSE) {
			error("%s: node must be IPv4/IPv6 address", subcmd);
			command_usage(EXIT_FAILURE);
		}
	}

	/* vni */
	if (ac > 1) {
		if (conv_vni(av[1], &vni, &errmsg) == FALSE) {
			error("%s: %s", subcmd, errmsg);
			command_usage(EXIT_FAILURE);
		}
	}

	/* check auguments */
	if (ac > 2) {
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/* open queue */
	open_queue_file(od, O_RDWR);

	/* check all vni */
	if (all_node) {
		QUE_queue_delete_all(vni);
	} else {
		QUE_queue_delete(utype, n, vni);
	}

	/* close queue */
	close_queue_file(od);
}

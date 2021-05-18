/*
 *  command_sync.c
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
#include "rule.h"

static const char* const subcmd = "sync";

static void
command_usage(int status)
{
	info("usage: [rule] %s %s [[utype] node]",
	     COMMAND_NAME, subcmd);
	info("\tutype    := \"auto\" | \"relay\" | \"member\" | \"both\"");
	info("\tnode     := \"all\" | \"backup\" | address");

	exit(status);
};

void
command_sync(OD *od, int ac, char *av[])
{
	ADDR node;
	ADDR *n = &node;
	int utype = QUE_UPDATE_AUTO;
	int all_node = 0;
	MLIST *p;

	/* check help */
	if (ac > 0 && strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	/* check update */
	if (ac > 0 && conv_que_update(av[0], &utype) == QUE_OK) {
		av ++;
		ac --;
	}

	/* check node */
	if (ac == 0 || strcasecmp(av[0], "all") == 0) {
		all_node = 1;
	} else if (utype == QUE_UPDATE_AUTO
		   && strcasecmp(av[0], "backup") == 0) {
		n = NULL;
	} else if (str_to_addr(av[0], n) == FALSE) {
		error("%s: node must be IPv4/IPv6 address", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check auguments */
	if (ac > 1) {
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  rule sync to disk
	 */
	open_rule_file(od, O_RDWR);
	sync_rule_file(od);
	close_rule_file(od);

	/*
	 *  queue sync
	 */
	open_queue_file(od, O_RDWR);
	if (all_node) {
		p = QUE_get_sync_list_all(NULL);
	} else {
		p = QUE_get_sync_list(NULL, utype, n);
	}
	if (p == NULL)
		crit_exit("out of memory ... aborted");
	close_queue_file(od);
	start_talkers(od, p);
}

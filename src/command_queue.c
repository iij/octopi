/*
 *  command_queue.c
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

static const char* const subcmd = "queue";

static void
command_usage(int status)
{
	info("usage: %s %s sub-command [arguments...]}", COMMAND_NAME, subcmd);
	info(" ");
        info("[sub-command]");
	info("\tinit, list, show, sync, add, delete, enable, disable, dump");
	exit(status);
};

static void
command_queue_help(OD *od, int ac, char *av[])
{
	command_usage(EXIT_SUCCESS);
}

static struct command_list {
	char *name;
	void (*func)(OD*, int, char **);
} commands[] = {
	{ "help",    command_queue_help,    },
	{ "init",    command_queue_init,    },
	{ "show",    command_queue_show,    },
	{ "list",    command_queue_list,    },
	{ "add",     command_queue_add,     },
	{ "delete",  command_queue_delete,  },
	{ "enable",  command_queue_enable,  },
	{ "disable", command_queue_disable, },
	{ "dump",    command_queue_dump,    },
	{ "sync",    command_sync,          },
	{ NULL,      NULL,                  },
};

void
command_queue(OD *od, int ac, char *av[])
{
	struct command_list *p;

	if (ac <= 0)
		command_usage(EXIT_FAILURE);

	for (p = commands; p->name; ++ p) {
		if (strcasecmp(p->name, av[0]) == 0) {
			p->func(od, ac - 1, av + 1);
			return;
		}
	}

	command_usage(EXIT_FAILURE);
}

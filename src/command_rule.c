/*
 *  command_rule.c
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

static const char* const subcmd = "[rule]";

static void
command_usage(int status)
{
	info("usage: %s %s sub-command [arguments...]}", COMMAND_NAME, subcmd);
	info(" ");
        info("[sub-command]");
	info("\tinit, show, list, find, add, delete, move, flush,");
	info("\tsave, restore, update, pause, unpause, sync, fsck, dump");
	exit(status);
};

static struct command_list {
	char *name;
	void (*func)(OD*, int, char **);
} commands[] = {
	{ "init",    command_init,    },
	{ "show",    command_show,    },
	{ "list",    command_list,    },
	{ "find",    command_find,    },
	{ "add",     command_add,     },
	{ "delete",  command_delete,  },
	{ "move",    command_move,    },
	{ "flush",   command_flush,   },
	{ "save",    command_save,    },
	{ "restore", command_restore, },
	{ "update",  command_update,  },
	{ "pause",   command_pause,   },
	{ "unpause", command_unpause, },
	{ "sync",    command_sync,    },
	{ "fsck",    command_fsck,    },
	{ "dump",    command_dump,    },
	{ NULL,      NULL,            },
};

void
command_rule(OD *od, int ac, char *av[])
{
	struct command_list *p;

	if (ac <= 0)
		command_usage(EXIT_FAILURE);

	if (strcasecmp(av[0], "help") == 0)
		command_usage(EXIT_SUCCESS);

	for (p = commands; p->name; ++ p) {
		if (strcasecmp(p->name, av[0]) == 0) {
			p->func(od, ac - 1, av + 1);
			break;
		}
	}
}

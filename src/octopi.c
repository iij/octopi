/*
 *  octopi.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>

#include "octopi.h"
#include "setproctitle.h"
#include "command.h"
#include "logging.h"

/*
 *  global variables
 */
OD oddata;

/*
 *  finish snipper process (dummy)
 */
void
finish_snipper()
{
	crit_exit("Internal Error: dummy pcap_breakloop is called");
}

/*
 *  show usage
 */
void
usage_and_exit(int status)
{
	info("usage: %s [options] command [arguments...]", COMMAND_NAME);
	info("[options]");
	info("\t-h         show this help messages (and exit)");
	info("\t-v         show version (and exit)");
	info("\t-c path    specify config file");
	info("\t-D oath    specify rule file");
	info("\t-Q path    specify queue file");
	info("\t-S number  maximum number of parallel synchronization");
	info("\t-d         debug mode");
	info("\t-n         dryrun mode");
	info("\t-q         quiet mode");
	info("\t-f         line-buffered mode");
	info(" ");
	info("[command]");
	info("\trule, queue, node, backup, acl,");
	info("\tinit, show, list, find, add, delete, move, flush,");
	info("\tsave, restore, update, pause, unpause, sync, fsck, dump");
	info("\thelp, version");
	info(" ");
	info("More detailed usages can be found in the following way.");
	info("\tie) octopi add help");
	info("\tie) octopi acl add help");
	exit(status);
}

/*
 *  show version
 */
void
version_and_exit(int status)
{
	info("%s version %s", COMMAND_NAME, COMMAND_VERSION);
	exit(status);
}

void
command_help(OD *od, int ac, char *av[])
{
	usage_and_exit(EXIT_SUCCESS);
}

void
command_version(OD *od, int ac, char *av[])
{
	version_and_exit(EXIT_SUCCESS);
}

/*
 *  command list
 */
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
	{ "pause",   command_pause,   },
	{ "unpause", command_unpause, },
	{ "save",    command_save,    },
	{ "restore", command_restore, },
	{ "update",  command_update,  },
	{ "sync",    command_sync,    },
	{ "fsck",    command_fsck,    },
	{ "dump",    command_dump,    },
	{ "queue",   command_queue,   },
	{ "node",    command_node,    },
	{ "backup",  command_backup,  },
	{ "acl",     command_acl,     },
	{ "rule",    command_rule,    },
	{ "help",    command_help,    },
	{ "version", command_version, },
	{ NULL,      NULL,            },
};

/*
 *  main routine
 */
int
main(int argc, char *argv[], char *envp[])
{
	OD *od = &oddata;
	int idx;
	struct command_list *p;

	/*
	 *  initialize process name
	 */
        setproctitle_init(argc, argv, envp);
	logging_init(COMMAND_NAME, LOG_USER);

	/*
	 *  initialize and read config
	 */
	initialize(od);
	idx = parse_args(od, argc, argv);
	readconf(od);
	od->proc_type = PROC_TYPE_COMMAND;
	logging_init(COMMAND_NAME, od->log_facility);

	/*
	 *  set standard I/O line bufferd
	 */
	if (od->foreground) {
		setvbuf(stdin,  NULL, _IOLBF, 0);
		setvbuf(stdout, NULL, _IOLBF, 0);
		setvbuf(stderr, NULL, _IOLBF, 0);
	}

	/*
	 *  setup rule and queue file
	 */
	if (od->opt_rule_file)
		od->rule_file = od->opt_rule_file;
	if (od->opt_queue_file)
		od->queue_file = od->opt_queue_file;

	/*
	 *  execute commands
	 */
	if (idx >= argc)
		usage_and_exit(EXIT_FAILURE);

	for (p = commands; p->name; ++ p) {
		if (strcasecmp(p->name, argv[idx]) == 0) {
			p->func(od, argc - idx - 1, argv + idx + 1);
			exit(EXIT_SUCCESS);
		}
	}

	error("%s: unknown command", COMMAND_NAME);
	usage_and_exit(EXIT_FAILURE);

	/* NOTREACHED */
	return EXIT_FAILURE;
}

/*
 *  octopid.c
 *
 *  copyright (c) 2019-2021 HANATAKA Shinya
 *  copyright (c) 2019-2021 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <syslog.h>

#include "octopi.h"
#include "logging.h"
#include "setproctitle.h"
#include "pidfile.h"

/*
 *  global variables
 */
OD oddata;

/*
 *  finish snipper process
 */
void
finish_snipper()
{
	OD *od = &oddata;
	pcap_breakloop(od->pcap);
}

/*
 *  fork child daemons
 */
static void
launcher(OD *od, int i)
{
	pid_t pid;
	struct od_child *child = od->child + i;

	if (child->pid != 0) {
		/* child is already running */
		debug("process (type = %d) %d was already luanched",
		      child->type, child->pid);
		return;
	}

	pid = fork();
	if (pid < 0) {
		/* fork error */
		alert("fork failed: %s", strerror(errno));
		return;
	} else if (pid) {
		/* parent */
		child->pid = pid;
		return;
	}

	/* child */
	od->proc_type = child->type;
	od->child_id = i;
	debug("process (type = %u) %d is luanched", od->proc_type, getpid());

	/* start child functions */
	switch (od->proc_type) {
	case PROC_TYPE_SNIPPER:
		snipper(od);
		break;
	case PROC_TYPE_DISPATCHER:
		dispatcher(od);
		break;
	case PROC_TYPE_CASTER:
		caster(od);
		break;
	case PROC_TYPE_LOGGER:
		logger(od);
		break;
	case PROC_TYPE_LISTENER:
		listener(od);
		break;
	case PROC_TYPE_KICKER:
		kicker(od);
		break;
	}

	/* NOTREACHED */
	crit_exit("BROKEN *** launcher failed (type = %d)", od->proc_type);
}

static int
check_loop(OD *od)
{
	int i;

	/* check terminate flag */
	if (od->terminate == 0)
		return TRUE;

	/* check childs */
	for (i = 0; i < od->num_childs; ++ i)
		if (od->child[i].pid)
			return TRUE;

	return FALSE;
}

static void
child_recover(OD *od, pid_t pid)
{
	int i;

	/* search child pid */
	for (i = 0; i < od->num_childs; ++ i)
		if (od->child[i].pid == pid)
			break;

	/* check not found */
	if (i >= od->num_childs) {
		alert("BROKEN *** unknown child process catched %d", pid);
		return;
	}

	/* re-launch child */
	od->child[i].pid = 0;
	if (od->terminate == 0)
		launcher(od, i);
}

/*
 *  show usage
 */
void
usage_and_exit(int status)
{
	info("usage: %s [options]", DAEMON_NAME);
	info("[options]");
	info("\t-h         show this help messages (and exit)");
	info("\t-v         show version (and exit)");
	info("\t-c path    specify config file");
	info("\t-D path    specify rule file");
	info("\t-Q path    specify queue file");
	info("\t-S number  maximum number of parallel synchronization");
	info("\t-d         debug mode");
	info("\t-n         dryrun mode");
	info("\t-q         quiet mode");
	info("\t-f         foreground (not-daemon) mode");
	info("\t-s         no-syslog mode");

	exit(status);
}

/*
 *  show version
 */
void
version_and_exit(int status)
{
	info("%s version %s", DAEMON_NAME, DAEMON_VERSION);
	exit(status);
}


/*
 *  main routine
 */
int
main(int argc, char *argv[], char *envp[])
{
	OD *od = &oddata;
	int idx;
	int i;

	/*
	 *  initialize process name
	 */
	setproctitle_init(argc, argv, envp);
	setproctitle("octopi-init");
	logging_init("octopi-init", LOG_USER);

	/*
	 *  initialize standard I/O buffer
	 */
        setvbuf(stdin,  NULL, _IOLBF, 0);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
	close_extra_files();

	/*
	 *  initialize signal handlers
	 */
	set_signal_hungup(SIGHUP);
	set_signal_terminate(SIGTERM);
	set_signal_terminate(SIGINT);
	set_signal_debug_on(SIGUSR1);
	set_signal_debug_off(SIGUSR2);

	/*
	 *  initialize and read config
	 */
	initialize(od);
	idx = parse_args(od, argc, argv);
	if (idx < argc)
		usage_and_exit(EXIT_FAILURE);
	readconf(od);

	/*
	 *  check dryrun-mode
	 */
	if (od->dryrun)
		exit(EXIT_SUCCESS);

	/*
	 *  lock pidfile
	 */
	if (od->pid_file)
		open_pidfile(od->pid_file);

	/*
	 *  setup process
	 */
	setup_proc(od);

	/*
	 *  daemonize
	 */
	if (!od->foreground)
		daemonize(od);
	if (od->pid_file)
		set_pidfile();
	
	/*
	 *  setup networks
	 */
	setup_network(od);

	/*
	 *  setup process name
	 */
	od->proc_type = PROC_TYPE_LAUNCHER;
	setproctitle("octopi-launcher");
	logging_init("octopi-launcher", od->log_facility);
	info("octopid started");

	/*
	 *  launch child process
	 */
	init_child(od);
	for (i = 0; i < od->num_childs; ++ i)
		launcher(od, i);

	/*
	 *  main loop
	 */
	while (check_loop(od)) {
		pid_t pid;
		int status;

		pid = wait(&status);

		if (pid < 0)
			continue;
		child_recover(od, pid);
	}

	return EXIT_SUCCESS;
}

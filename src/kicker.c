/*
 *  kicker.c
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "octopi.h"
#include "logging.h"
#include "setproctitle.h"
#include "rule.h"
#include "que.h"

static int
check_loop(OD *od, MLIST *p, MLIST *target)
{
	int i;

	/* check one-shot */
	if (target && p->pos >= p->num)
		od->terminate = 1;

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
fork_talker(OD* od, MLIST *p)
{
	int i;
	pid_t pid;

	while (od->terminate == 0 && p->pos < p->num) {
		/*  search open slot */
		for (i = 0; i < od->num_childs; ++ i) {
			if (od->child[i].pid == 0)
				break;
		}
		if (i >= od->num_childs)
			break;

		/* new process */
		pid = fork();
		if (fork < 0) {
			alert("fork failed: %s", strerror(errno));
			od->terminate = 1;
			return;
		}

		if (pid == 0) {
			/* child */
			od->proc_type = PROC_TYPE_TALKER;
			od->child_id = i;
			od->num_childs = 0;
			talker(od, p->member[p->pos]);

			/* NOTREACHED */
			crit_exit("BROKEN *** launcher failed (type = %d)",
				  od->proc_type);
		}

		/* parent */
		p->pos ++;
		od->child[i].pid = pid;
	}
}

static int
check_interval(OD *od, struct timeval *s)
{
	struct timeval now;
	int64_t left;

	/*
	 *  check terminate
	 */
	if (od->terminate)
		return 0;

	/*
	 *  time difference [mili second]
	 */
	gettimeofday(&now, NULL);
	left = od->sync_interval
		- (now.tv_sec - s->tv_sec) * 1000
		- (now.tv_usec - s->tv_usec) / 1000;

	if (left > 0)
		return 0;

	return 1;
}

static int
count_childs(OD *od)
{
	int count = 0;
	int i;

	for (i = 0; i < od->num_childs; ++ i) {
		if (od->child[i].pid != 0) {
			count ++;
		}
	}

	return count;
}

static void
reap_childs(OD *od)
{
	pid_t pid;
	int status;
	int i;
	int flag = WNOHANG;

	while (count_childs(od) > 0) {
		/* check terminate flag */
		if (od->terminate)
			flag = 0;

		/* wait child */
		pid = waitpid(-1, &status, flag);
		if (pid < 0) {
			if (errno == EINTR) {
				/* interrupted */
				continue;
			} else if (errno == ECHILD) {
				/* There is no child */
				break;
			}
			error_exit("waitpid failed %s", strerror(errno));
		} else if (pid == 0) {
			/* No waiting child */
			break;
		}

		/* remove from child list */
		for (i = 0; i < od->num_childs; ++ i) {
			if (od->child[i].pid == pid) {
				od->child[i].pid = 0;
				break;
			}
		}
		if (i >= od->num_childs) {
			alert("BROKEN *** unknown child process catched %d",
			      pid);
		}
	}
}

static void
wait_interval(OD *od, struct timeval *s)
{
	struct timeval timeout;
	struct timeval now;
	int64_t left;

	/*
	 *  calculate left time
	 */
	gettimeofday(&now, NULL);
	left = od->sync_interval
		- (now.tv_sec - s->tv_sec) * 1000
		- (now.tv_usec - s->tv_usec) / 1000;

	/*
	 *  sleep for interval (or receive signal)
	 */
	if (left > 0) {
		if (left > 5000 && count_childs(od) > 0)
			left = 5000; /* mili second */
		timeout.tv_sec  = left / 1000;
		timeout.tv_usec = (left % 1000) * 1000;
		select(0, NULL, NULL, NULL, &timeout);
	}
}

static void
init_talker_child(OD *od)
{
	int i;

	od->num_childs = od->talker_procs;
	od->child = (struct od_child *)
		malloc(od->num_childs * sizeof(struct od_child));
	if (od->child == NULL)
		crit_exit("out of memory ... aborted");
	memset(od->child, 0, (od->num_childs * sizeof(struct od_child)));

	for (i = 0; i < od->num_childs; ++ i)
		od->child[i].type = PROC_TYPE_TALKER;
}

static MLIST *
init_member_list(OD *od, MLIST *p)
{
	open_queue_file(od, O_RDWR);
	p = QUE_get_sync_list_all(p);
	if (p == NULL)
		crit_exit("out of memory ... aborted");
	close_queue_file(od);

	return p;
}

void
start_talkers(OD *od, MLIST *target)
{
	MLIST *p;
	struct timeval start;

	/*
	 *  initialize child list
	 */
	init_talker_child(od);

	/*
	 *  initialize member list
	 */
	gettimeofday(&start, NULL);
	if (target)
		p = target;
	else
		p = init_member_list(od, NULL);

	/*
	 *  setup signals
	 */
	set_signal_blank(SIGCHLD);
	set_signal_hungup(SIGHUP);
	set_signal_terminate(SIGTERM);
	set_signal_terminate(SIGINT);
	set_signal_debug_on(SIGUSR1);
	set_signal_debug_off(SIGUSR2);

	/*
	 *  main lopp
	 */
	while (check_loop(od, p, target)) {
		/* refill member list each interval. */
		if (target == NULL && check_interval(od, &start)) {
			gettimeofday(&start, NULL);
			p = init_member_list(od, p);
		}

		/*  do sync */
		fork_talker(od, p);

		/* wait kick interval */
		wait_interval(od, &start);

		/* reap childs */
		reap_childs(od);
	}

	/*
	 *  free member list
	 */
	QUE_free_mlist(p);
}

void
kicker(OD *od)
{
	setproctitle("octopi-kicker");
	logging_init("octopi-kicker", od->log_facility);

	start_talkers(od, NULL);

	exit(EXIT_SUCCESS);
}

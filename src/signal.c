/*
 *  signal.c
 *
 *  copyright (c) 2019-2021 HANATAKA Shinya
 *  copyright (c) 2019-2021 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>

#include "octopi.h"
#include "logging.h"

extern OD oddata;

static void
kill_childs(OD *od, int signo)
{
	int i;

	for(i = 0; i < od->num_childs; ++ i)
		if (od->child[i].pid != 0) {
			debug("send signal %d to %d",
			      signo, od->child[i].pid);
			kill(od->child[i].pid, signo);
		}
}

static void
blank_signal_handler(int signo)
{
	debug("signal %d is caught", signo);
	return;
}

static void
terminate_signal_handler(int signo)
{
	OD *od = &oddata;

	debug("signal %d is caught", signo);

	od->terminate = 1;
	switch (od->proc_type) {
	case PROC_TYPE_INIT:
		_exit(0);
	case PROC_TYPE_LAUNCHER:
	case PROC_TYPE_COMMAND:
	case PROC_TYPE_KICKER:
		kill_childs(od, signo);
		break;
	case PROC_TYPE_SNIPPER:
		finish_snipper();
		break;
	}
}

static void
hungup_signal_handler(int signo)
{
	OD *od = &oddata;

	debug("signal %d is caught", signo);

	if (od->proc_type == PROC_TYPE_LAUNCHER)
		kill_childs(od, signo);
	else
		od->terminate = 1;
}

static void
debug_on_signal_handler(int signo)
{
	OD *od = &oddata;

	debug("signal %d is caught", signo);
	od->debug = 1;
	debug_on();
	debug("debug mode on");
}

static void
debug_off_signal_handler(int signo)
{
	OD *od = &oddata;

	debug("signal %d is caught", signo);
	debug("debug mode off");
	od->debug = 0;
	debug_off();
}

inline int
set_signal(int signo, void (*handler)(int))
{
        struct sigaction sa;

        sigfillset(&sa.sa_mask);
        sa.sa_handler = handler;
	if (signo == SIGCHLD) {
		sa.sa_flags = SA_NOCLDSTOP;
		if (handler == SIG_IGN)
			sa.sa_flags |= SA_NOCLDWAIT;
	}

        return sigaction(signo, &sa, NULL);
}

void
set_signal_blank(int signo)
{
	set_signal(signo, blank_signal_handler);
}

void
set_signal_hungup(int signo)
{
	set_signal(signo, hungup_signal_handler);
}

void
set_signal_terminate(int signo)
{
	set_signal(signo, terminate_signal_handler);
}

void
set_signal_debug_on(int signo)
{
	set_signal(signo, debug_on_signal_handler);
}

void
set_signal_debug_off(int signo)
{
	set_signal(signo, debug_off_signal_handler);
}

void
set_signal_ignore(int signo)
{
	set_signal(signo, SIG_IGN);
}

void
block_signals(OD *od)
{
	sigset_t mask;

	debug("block signals");
	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);

	while (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		if (errno != EINTR)
			error_exit("sigprocmask(BLOCK) failed: %s",
				   strerror(errno));
	}
}

void
unblock_signals(OD *od)
{
	sigset_t mask;

	debug("unblock signals");
	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);

	while (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		if (errno != EINTR)
			error_exit("sigprocmask(UNBLOCK) failed: %s",
				   strerror(errno));
	}
}

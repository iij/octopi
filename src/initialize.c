/*
 *  initialize.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "octopi.h"
#include "logging.h"
#include "token.h"

static ADDR *
init_addr(char *addr)
{
	ADDR *a;

	a = malloc(sizeof(ADDR));
	if (a == NULL)
		crit_exit("out of memory ... aborted");

	if (str_to_addr(addr, a) == FALSE) {
		a->af        = AF_INET6;
		a->mask      = 128;
		a->next      = NULL;
		a->ipv6_addr = 0;
	}

	return a;
}

static ADDR *
init_cidr(char *addr)
{
	ADDR *a;

	a = malloc(sizeof(ADDR));
	if (a == NULL)
		crit_exit("out of memory ... aborted");

	if (str_to_cidr(addr, a) == FALSE) {
		a->af        = AF_INET;
		a->mask      = 8;
		a->next      = NULL;		
		a->ipv4_addr = inet_addr("239.0.0.0");
	}

	return a;
}

static uid_t
init_user(char *name)
{
	uid_t user;

	if (str_to_uid(name, &user, MAX_USER) == FALSE)
		if (str_to_uid("nobody", &user, MAX_USER) == FALSE)
			user = MAX_USER;

	return user;
}

static gid_t
init_group(char *name)
{
	gid_t group;

	if (str_to_gid(name, &group, MAX_GROUP) == FALSE)
		if (str_to_gid("nogroup", &group, MAX_GROUP) == FALSE)
			group = MAX_GROUP;

	return group;
}

void
initialize(OD *od)
{

	/*
	 *  initizalize IPv4/IPv6 netmasks
	 */
	init_netmasks();

	/*
	 *  initialize config data
	 */
	memset(od, 0, sizeof(OD));
	od->proc_type          = PROC_TYPE_INIT;
	od->child_id           = -1;
	od->config_file        = DEFAULT_CONFIG_FILE;
	od->rule_file          = DEFAULT_RULE_FILE;
	od->queue_file         = DEFAULT_QUEUE_FILE;
	od->pid_file           = NULL;
	od->interface          = DEFAULT_INTERFACE;
	od->vxlan_port         = DEFAULT_VXLAN_PORT;
	od->relay_port         = DEFAULT_RELAY_PORT;
	od->sync_port          = DEFAULT_SYNC_PORT;
	od->sync_address       = init_addr(DEFAULT_SYNC_ADDRESS);
	od->multicast          = init_cidr(DEFAULT_MULTICAST);
	od->caster_ttl         = DEFAULT_CASTER_TTL;
	od->log_facility       = DEFAULT_LOG_FACILITY;
	od->log_interval       = DEFAULT_LOG_INTERVAL;
	od->user               = init_user(DEFAULT_USER);
	od->group              = init_group(DEFAULT_GROUP);
	od->pool_size          = DEFAULT_POOL_SIZE;
	od->hash_size          = DEFAULT_HASH_SIZE;
	od->que_pool_size      = DEFAULT_QUE_POOL_SIZE;
	od->que_hash_size      = DEFAULT_QUE_HASH_SIZE;
	od->timeout            = DEFAULT_TIMEOUT;
	od->sync_timeout       = DEFAULT_SYNC_TIMEOUT;
	od->sync_interval      = DEFAULT_SYNC_INTERVAL;
	od->sync_buffer        = DEFAULT_SYNC_BUFFER;
	od->snipper_procs      = DEFAULT_SNIPPER;
	od->dispatcher_procs   = DEFAULT_DISPATCHER;
	od->caster_procs       = DEFAULT_CASTER;
	od->logger_procs       = DEFAULT_LOGGER;
	od->listener_procs     = DEFAULT_LISTENER;
	od->kicker_procs       = DEFAULT_KICKER;
	od->talker_procs       = DEFAULT_TALKER;
}

/*
 *  parse command line arguments
 */
uint32_t
parse_num(char *str, char *tag, uint32_t min, uint32_t max)
{
	char *end;
	uint32_t num = strtoul(str, &end, 0);

	if (*end != '\0')
		error_exit("option %s needs a number", tag);

	/*
	 *  check range
	 */
	if (num < min)
		error_exit("option %s %s is too small (minimum %u)",
			   tag, str, min);

	if (num > max)
		error_exit("option %s %s is too large (maximum %u)",
			   tag, str, max);

	return num;

}

int
parse_args(OD *od, int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "hvc:D:Q:S:dnqfs")) != -1) {
		switch (opt) {
		case 'h':
			usage_and_exit(EXIT_SUCCESS);
			/* NOTREACHED */
			break;
		case 'v':
			version_and_exit(EXIT_SUCCESS);
			/* NOTREACHED */
			break;
		case 'c':
			od->config_file = optarg;
			break;
		case 'D':
			od->opt_rule_file = optarg;
			break;
		case 'Q':
			od->opt_queue_file = optarg;
			break;
		case 'S':
			od->opt_talker_procs
				= parse_num(optarg, "-S", 1, MAX_TALKER);
			break;
		case 'd':
			od->debug = 1;
			break;
		case 'n':
			od->dryrun = 1;
			break;
		case 'q':
			od->quiet = 1;
			break;
		case 'f':
			od->foreground = 1;
			break;
		case 's':
			od->no_syslog = 1;
			break;
		default:
			usage_and_exit(EXIT_FAILURE);
			/* NOTREACHED */
		}
	}

	if (od->debug)
		debug_on();

	if (od->quiet)
		logging_stop_stderr();

	return optind;
}

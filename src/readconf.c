/*
 *  readconf.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "octopi.h"
#include "logging.h"
#include "token.h"
#include "ioutil.h"

/*
 *  parse config file
 */
static void
parse_conf(OD *od, char *buf, int lnum)
{
	char *fname = od->config_file;
	char *cur;
	char *tag;

	cur = buf;
	tag = get_token(&cur);

	if (tag == NULL)
		return;

	if (strcmp(tag, "debug") == 0)
		od -> debug = read_debug(fname, lnum, "debug", &cur);

	else if (strcmp(tag, "rule_file") == 0)
		od->rule_file = read_str(fname, lnum, "rule_file", &cur, 0, 0);

	else if (strcmp(tag, "queue_file") == 0)
		od->queue_file = read_str(fname, lnum, "queue_file",
					  &cur, 0, 0);

	else if (strcmp(tag, "pid_file") == 0)
		od->pid_file = read_str(fname, lnum, "pid_file",
					&cur, 0, 0);

	else if (strcmp(tag, "interface") == 0)
		od->interface = read_str(fname, lnum, "interface", &cur,
					 MIN_IFNAME_LEN, MAX_IFNAME_LEN);

	else if (strcmp(tag, "address") == 0)
		od->address = read_addr(fname, lnum, "address", &cur);

	else if (strcmp(tag, "sync_address") == 0)
		od->sync_address = read_addr(fname, lnum,
					     "sync_address", &cur);

	else if (strcmp(tag, "vxlan_port") == 0)
		od->vxlan_port = read_num(fname, lnum, "vxlan_port", &cur,
					  1, MAX_PORT);

	else if (strcmp(tag, "relay_port") == 0)
		od->relay_port = read_num(fname, lnum, "relay_port", &cur,
					  1, MAX_PORT);

	else if (strcmp(tag, "sync_port") == 0)
		od->sync_port = read_num(fname, lnum, "sync_port", &cur,
					1, MAX_PORT);

	else if (strcmp(tag, "multicast") == 0)
		od->multicast = read_cidr(fname, lnum, "mullticast", &cur);

	else if (strcmp(tag, "caster_ttl") == 0)
		od->caster_ttl = read_num(fname, lnum, "caster_ttl", &cur,
					  1, MAX_CASTER_TTL);

	else if (strcmp(tag, "log_facility") == 0)
		od->log_facility = read_log_facility(fname, lnum,
						     "log_facility", &cur);

	else if (strcmp(tag, "log_interval") == 0)
		od->log_interval = read_num(fname, lnum, "log_interval", &cur,
					    0, MAX_LOG_INTERVAL);

	else if (strcmp(tag, "user") == 0)
		od->user = read_user(fname, lnum, "user", &cur, MAX_USER);

	else if (strcmp(tag, "group") == 0)
		od->group = read_group(fname, lnum, "group", &cur, MAX_GROUP);

	else if (strcmp(tag, "pool_size") == 0)
		od->pool_size = read_num(fname, lnum, "pool_size", &cur,
					 MIN_POOL_SIZE, MAX_POOL_SIZE);

	else if (strcmp(tag, "hash_size") == 0)
		od->hash_size = read_num(fname, lnum, "hash_size", &cur,
					 MIN_HASH_SIZE, MAX_HASH_SIZE);

	else if (strcmp(tag, "queue_pool_size") == 0)
		od->que_pool_size = read_num(fname, lnum, "queue_pool_size",
					     &cur,
					     MIN_QUE_POOL_SIZE,
					     MAX_QUE_POOL_SIZE);

	else if (strcmp(tag, "queue_hash_size") == 0)
		od->que_hash_size = read_num(fname, lnum, "queue_hash_size",
					     &cur,
					     MIN_QUE_HASH_SIZE,
					     MAX_QUE_HASH_SIZE);

	else if (strcmp(tag, "secret") == 0)
		od->secret = read_str(fname, lnum, "secret", &cur,
				      1, SECRET_LEN);

	else if (strcmp(tag, "timeout") == 0)
		od->timeout = read_num(fname, lnum, "timeout", &cur,
				       0, MAX_TIMEOUT);

	else if (strcmp(tag, "sync_timeout") == 0)
		od->sync_timeout = read_num(fname, lnum, "sync_timeout", &cur,
					   MIN_SYNC_TIMEOUT,
					   MAX_SYNC_TIMEOUT);

	else if (strcmp(tag, "sync_interval") == 0)
		od->sync_interval = read_num(fname, lnum, "sync_interal", &cur,
					     MIN_SYNC_INTERVAL,
					     MAX_SYNC_INTERVAL);

	else if (strcmp(tag, "sync_buffer") == 0)
		od->sync_buffer = read_num(fname, lnum, "sync_buffer", &cur,
					   1024, MAX_SYNC_BUFFER);

	else if (strcmp(tag, "snipper_procs") == 0)
		od->snipper_procs = read_num(fname, lnum,
					     "snipper_procs", &cur,
					     0, MAX_SNIPPER);

	else if (strcmp(tag, "dispatcher_procs") == 0)
		od->dispatcher_procs = read_num(fname, lnum,
						"dispatcher_procs", &cur,
						0, MAX_DISPATCHER);

	else if (strcmp(tag, "caster_procs") == 0)
		od->caster_procs = read_num(fname, lnum,
					    "caster_procs", &cur,
					    0, MAX_CASTER);

	else if (strcmp(tag, "logger_procs") == 0)
		od->logger_procs = read_num(fname, lnum,
					    "loggerr_procs", &cur,
					    0, MAX_LOGGER);

	else if (strcmp(tag, "listener_procs") == 0)
		od->listener_procs = read_num(fname, lnum,
					      "listener_procs", &cur,
					      0, MAX_LISTENER);

	else if (strcmp(tag, "kicker_procs") == 0)
		od->kicker_procs = read_num(fname, lnum,
					    "kicker_procs", &cur,
					    0, MAX_KICKER);

	else if (strcmp(tag, "talker_procs") == 0)
		od->talker_procs = read_num(fname, lnum,
					    "talkker_procs", &cur,
					    1, MAX_TALKER);

	else
		error_exit("%s:%d unknown config %s", fname, lnum, tag);
}

/*
 *  open and read  config file
 */
void
readconf(OD *od)
{
	FILE *fp;
	int linenum = 0;

	/*
	 *  open config file
	 */
	fp =  fopen(od->config_file, "r");
	if (fp == NULL)
		error_exit("open failed: %s: %s",
			   od->config_file, strerror(errno));

	/*
	 *  read config file
	 */
	while (1) {
		char buf[MAX_LINE_LEN];
		int len;

		/*
		 *  read next line
		 */
		linenum ++;
		len = xgets(buf, MAX_LINE_LEN, fp);
		if (len <= 0)
			break;

		/*
		 *  check line length
		 */
		if (buf[len - 1] != '\n')
			error_exit("%s:%d line is too long",
				   od->config_file, linenum);

		/*
		 *  parse config line
		 */
		parse_conf(od, buf, linenum);
	}

	/*
	 *  check read error
	 */
	if (feof(fp) == 0)
		error_exit("%s read failed: %s",
			   od->config_file, strerror(errno));

	/*
	 *  close config file
	 */
	fclose(fp);

	/*
	 *  setup rule file and queue file
	 */
	if (od->opt_rule_file)
		od->rule_file = od->opt_rule_file;
	if (od->opt_queue_file)
		od->queue_file = od->opt_queue_file;
	if (od->opt_talker_procs)
		od->talker_procs = od->opt_talker_procs;

	/*
	 *  debug output
	 */
#define PRTAG "%-20.20s "
	debug(PRTAG "%d", "proc_type:",          od->proc_type);
	debug(PRTAG "%d", "terminate:",          od->terminate);
	debug(PRTAG "%s", "config_file:",        od->config_file);
	if (od->opt_rule_file)
		debug(PRTAG "%s", "opt_rule_file:",      od->opt_rule_file);
	debug(PRTAG "%s", "rule_file:",          od->rule_file);
	if (od->opt_queue_file)
		debug(PRTAG "%s", "opt_queue_file:",     od->opt_queue_file);
	debug(PRTAG "%s", "queue_file:",         od->queue_file);
	if (od->pid_file)
		debug(PRTAG "%s", "pid_file:",           od->pid_file);	
	debug(PRTAG "%d", "debug:",              od->debug);
	debug(PRTAG "%d", "dryrun:",             od->dryrun);
	debug(PRTAG "%d", "quiet:",              od->quiet);
	debug(PRTAG "%d", "foreground:",         od->foreground);
	debug(PRTAG "%d", "no_syslog:",          od->no_syslog);
	debug(PRTAG "%s", "queue_file:",         od->queue_file);
	debug(PRTAG "%s", "interface:",          od->interface);
	{
		ADDR *p;
		char buf[CIDR_STR_LEN];
		for (p = od->address; p; p = p->next) {
			if (addr_to_str(p, buf) == TRUE)
				debug(PRTAG "%s", "address:", buf);
		}
	}
	{
		ADDR *p;
		char buf[CIDR_STR_LEN];
		for (p = od->sync_address; p; p = p->next) {
			if (addr_to_str(p, buf) == TRUE)
				debug(PRTAG "%s", "sync_address:", buf);
		}
	}
	debug(PRTAG "%u", "vxlan_port:",        od->vxlan_port);
	debug(PRTAG "%u", "relay_port:",        od->relay_port);
	debug(PRTAG "%u", "sync_port:",         od->sync_port);
	{
		ADDR *p;
		char buf[CIDR_STR_LEN];
		for (p = od->multicast; p; p = p->next) {
			if (cidr_to_str(p, buf) == TRUE)
				debug(PRTAG "%s", "multicast:", buf);
		}
	}
	debug(PRTAG "%u", "caster_ttl:",         od->caster_ttl);
	debug(PRTAG "%04x", "log_facility:",     od->log_facility);
	debug(PRTAG "%u", "log_interval:",       od->log_interval);
	debug(PRTAG "%d", "user:",               od->user);
	debug(PRTAG "%d", "group:",              od->group);
	debug(PRTAG "%u", "pool_size:",          od->pool_size);
	debug(PRTAG "%u", "hash_size:",          od->hash_size);
	debug(PRTAG "%u", "queue_pool_size:",    od->que_pool_size);
	debug(PRTAG "%u", "queue_hash_size:",    od->que_hash_size);
	if (od->secret)
		debug(PRTAG "%s", "secret:",     od->secret);
	debug(PRTAG "%u", "timeout:",            od->timeout);
	debug(PRTAG "%u", "sync_timeout:",       od->sync_timeout);
	debug(PRTAG "%u", "sync_interval:",      od->sync_interval);
	debug(PRTAG "%u", "sync_buffer:",        od->sync_buffer);
	debug(PRTAG "%u", "snipper_procs:",      od->snipper_procs);
	debug(PRTAG "%u", "dispatcher_procs:",   od->dispatcher_procs);
	debug(PRTAG "%u", "caster_procs:",       od->caster_procs);
	debug(PRTAG "%u", "logger_procs:",       od->logger_procs);
	debug(PRTAG "%u", "listener_procs:",     od->listener_procs);
	debug(PRTAG "%u", "kicker_procs:",       od->kicker_procs);
	if (od->opt_talker_procs)
		debug(PRTAG "%u", "opt_talker_procs",   od->opt_talker_procs);
	debug(PRTAG "%u", "talker_procs:",       od->talker_procs);
}

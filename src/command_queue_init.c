/*
 *  command_queue_init.c
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
#include "command.h"
#include "addrutil.h"
#include "logging.h"
#include "rule.h"

static const char* const subcmd = "queue";
static const char* const optcmd = "init";

static void
command_usage(int status)
{
	info("usage: %s %s %s [pool_size [hash_size]]",
	     COMMAND_NAME, subcmd, optcmd);
	info("\tpool_size := number (%u ... %u)",
	     MIN_QUE_POOL_SIZE, MAX_QUE_POOL_SIZE);
	info("\thash_size := number (%u ... %u)",
	     MIN_QUE_HASH_SIZE, MAX_QUE_HASH_SIZE);
	exit(status);
};

void
command_queue_init(OD *od, int ac, char *av[])
{
	uint32_t pool_size = od->que_pool_size;
	uint32_t hash_size = od->que_hash_size;

	if (ac > 0) {
		/* check help */
		if (strcasecmp(av[0], "help") == 0)
			command_usage(EXIT_SUCCESS);

		/* pool size */
		if (str_to_uint32(av[0], &pool_size) == FALSE) {
			error("%s: pool_size must be a number", subcmd);
			command_usage(EXIT_FAILURE);
		}
		if (pool_size > MAX_QUE_POOL_SIZE) {
			error("%s: pool_size is too large", subcmd);
			command_usage(EXIT_FAILURE);
		}
		if (pool_size < MIN_QUE_POOL_SIZE) {
			error("%s: pool_size is too small", subcmd);
			command_usage(EXIT_FAILURE);
		}
	}

	/* hash size */
	if (ac > 1) {
		if (str_to_uint32(av[1], &hash_size) == FALSE) {
			error("%s: hash_size must be a number", subcmd);
			command_usage(EXIT_FAILURE);
		}
		if (hash_size > MAX_QUE_HASH_SIZE) {
			error("%s: pool_size is too large", subcmd);
			command_usage(EXIT_FAILURE);
		}
		if (hash_size < MIN_QUE_HASH_SIZE) {
			error("%s: pool_size is too small", subcmd);
			command_usage(EXIT_FAILURE);
		}
	}

	/* check garbage */
	if (ac > 2) {
		error("%s: too many auguments", subcmd);
		command_usage(EXIT_FAILURE);
	}

	/* check dryrun */
	if (od->dryrun)
		return;

	/*
	 *  init
	 */
	init_queue_file(od, pool_size, hash_size);
}

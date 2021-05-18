/*
 *  logger.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "octopi.h"
#include "logging.h"
#include "setproctitle.h"

static void
log_packet_count(OD *od, int type, char *header)
{
	COUNTER sum;
	int i, j;
	volatile struct od_stat_set *c;

	memset((void*)&sum, 0, sizeof(COUNTER));
	for (i = 0; i < od->num_childs; ++i) {
		if (od->child[i].type != type)
			continue;

		c = od->counter->child + i;
		for (j = 0; j < NUM_COUNTER; ++ j) {
			uint32_t count = c->count.packet[j];
			uint32_t last = c->last.packet[j];

			sum.packet[j] += count - last;
			c->last.packet[j] = count;
		}
	}
	info("%s recv %u sent %u drop %u recv %u",
	     header, sum.recv, sum.sent, sum.drop, sum.error);
}

static int
wait_interval(OD *od, time_t now)
{
	time_t now_period = now / od->log_interval;
	time_t last_period = od->counter->time / od->log_interval;

	if (now_period <= last_period) {
		time_t wait = (last_period + 1) * od->log_interval - now;

		if (wait <= 0)
			wait = 1;
		sleep(wait);
		return TRUE;
	}

	od->counter->time = now;
	return FALSE;
}

void
logger(OD *od)
{
	setproctitle("octopi-logger");
	logging_init("octopi-logger", od->log_facility);

	/*
	 *  initialize __timezone
	 */
	tzset();

	/*
	 *  initialize time
	 */
	if (od->counter->time == 0) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		od->counter->time = tv.tv_sec - __timezone;
	}

	/*
	 *  check disable
	 */
	while (od->terminate == 0) {
		struct timeval tv;
		if (od->log_interval == 0) {
			pause();
			continue;
		}

		/*
		 *  wait log interrval
		 */
		gettimeofday(&tv, NULL);
		if (wait_interval(od, tv.tv_sec - __timezone) == TRUE)
			continue;

		/*
		 *  log packet count
		 */
		log_packet_count(od, PROC_TYPE_SNIPPER, "snipper");
		log_packet_count(od, PROC_TYPE_DISPATCHER, "dispatcher");
		log_packet_count(od, PROC_TYPE_CASTER, "caster");
	}

	exit(EXIT_SUCCESS);
}

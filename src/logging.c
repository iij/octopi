/*
 *  logging.c
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <syslog.h>

#include "ioutil.h"
#include "logging.h"

int logging_debug  = 0;
static int logging_syslog = 0;
static int logging_stderr = 1;
static char *app_name;

static struct log_type {
	int priority;
	char *name;
} logtype[] = {
	{ LOG_DEBUG,   "NONE",    },
	{ LOG_DEBUG,   "DEBUG",   },
	{ LOG_INFO,    "INFO",    },
	{ LOG_NOTICE,  "NOTICE",  },
	{ LOG_WARNING, "WARN",    },
	{ LOG_ERR,     "ERROR",   },
	{ LOG_CRIT,    "CRIT",    },
	{ LOG_ALERT,   "ALERT",   },
	{ LOG_EMERG,   "EMERG",   },
};

static char *
time_now(void)
{
	static char tstr[20]; /* YYYY-MM-DD hh:mm:ss */
	time_t t;
	struct tm tm_buf;
	struct tm *tm;

	t = time(NULL);
	tm = localtime_r(&t, &tm_buf);
	snprintf(tstr, 20, "%04d-%02d-%02d %02d:%02d:%02d",
		 tm -> tm_year + 1900, tm -> tm_mon + 1, tm -> tm_mday,
		 tm -> tm_hour, tm -> tm_min, tm -> tm_sec);

	return tstr;
}

static void
output_log(int level, char *format, va_list ap)
{
	char logbuf[LOG_MSG_LEN];

	if (level < 0)
		return;
	if (level > LT_EMERG)
		level = LT_EMERG;

	/*
	 *  format log message
	 */
	vsnprintf(logbuf, LOG_MSG_LEN, format, ap);

	/*
	 *  output log messages
	 */
	if (logging_stderr) {
		if (logging_debug) {
			fprintf(stderr, "%s %s[%d]: %s %.*s\n",
				time_now(), app_name, getpid(),
				logtype[level].name, LOG_MSG_LEN, logbuf);
		} else {
			fprintf(stderr, "%.*s\n", LOG_MSG_LEN, logbuf);
		}
	}

	/*
	 *  output syslog
	 */
	if (logging_syslog)
		syslog(logtype[level].priority, "%s %.*s",
		       logtype[level].name, LOG_MSG_LEN, logbuf);
}

void
logging(int level, char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	output_log(level, format, ap);
	va_end(ap);
}

void
debug_on()
{
	logging_debug = 1;
}

void
debug_off()
{
	logging_debug = 0;
}

void
logging_init(char* name, int facility)
{
	app_name = name;
	openlog(app_name, LOG_PID, facility);
}

void
logging_start_syslog()
{
	logging_syslog = 1;
}

void
logging_stop_syslog()
{
	logging_syslog = 0;
}

void
logging_start_stderr()
{
	logging_stderr = 1;
}

void
logging_stop_stderr()
{
	logging_stderr = 0;
}

void
debug_packet(const char *header, const uint8_t *buf, const int len)
{
	char logbuf[LOG_MSG_LEN];
	size_t offset = 0;
	int i;

	if (logging_debug == 0)
		return;

	logging(LT_DEBUG, "packet: %s len=%d", header, len);
	for (i = 0; i < len; ++ i) {
		xprintf(logbuf, &offset, LOG_MSG_LEN, " %02x", buf[i]);
		if (i % 16 == 15) {
			logging(LT_DEBUG, "%s", logbuf);
			offset = 0;
		}
	}
	if (i % 16 != 15) {
		logging(LT_DEBUG, "%s", logbuf);
	}
}

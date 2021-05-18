/*
 *  octopi.h
 *
 *  copyright (c) 2019-2021 HANATAKA Shinya
 *  copyright (c) 2019-2021 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _OCTOPID_H
#define _OCTOPID_H

#include <stdint.h>
#include <syslog.h>
#include <time.h>
#include <pcap.h>

#include "addrutil.h"

#ifndef CONFDIR
#define CONFDIR  "/opt/octopi"
#endif

#ifndef DATADIR
#define DATADIR  "/opt/octopi"
#endif

#define DAEMON_NAME             "octopid"
#define DAEMON_VERSION          "1.98"
#define COMMAND_NAME            "octopi"
#define COMMAND_VERSION         "1.98"

#define MAX_LINE_LEN            (2048)
#define MAX_PCAP_FILTER         (2048)
#define MAX_PACKET_SIZE         (10240)
#define SYNC_IO_SIZE             (4096)

#define DEFAULT_CONFIG_FILE     CONFDIR "/octopi.conf"
#define DEFAULT_RULE_FILE       DATADIR "/octopidb"
#define DEFAULT_QUEUE_FILE      DATADIR "/octopiqueue"
#define DEFAULT_INTERFACE       "eth0"
#define DEFAULT_VXLAN_PORT      (4789)
#define DEFAULT_RELAY_PORT      (14789)
#define DEFAULT_SYNC_PORT       (24789)
#define DEFAULT_SYNC_ADDRESS    "::"
#define DEFAULT_MULTICAST       "239.0.0.0/8"
#define DEFAULT_CASTER_TTL      (1)
#define DEFAULT_LOG_FACILITY    (LOG_LOCAL0)
#define DEFAULT_LOG_INTERVAL    (300)
#define DEFAULT_USER            "daemon"
#define DEFAULT_GROUP           "daemon"
#define DEFAULT_POOL_SIZE       (1000000)
#define DEFAULT_HASH_SIZE       (213131)
#define DEFAULT_QUE_POOL_SIZE   (100000)
#define DEFAULT_QUE_HASH_SIZE   (21313)
#define DEFAULT_TIMEOUT         (0)
#define DEFAULT_SYNC_TIMEOUT    (60000)
#define DEFAULT_SYNC_INTERVAL   (60000)
#define DEFAULT_SYNC_BUFFER     (65536)
#define DEFAULT_SNIPPER         (1)
#define DEFAULT_DISPATCHER      (8)
#define DEFAULT_CASTER          (4)
#define DEFAULT_LOGGER          (1)
#define DEFAULT_LISTENER        (0)
#define DEFAULT_KICKER          (0)
#define DEFAULT_TALKER          (8)

#define SECRET_LEN              (16)
#define MIN_IFNAME_LEN          (1)
#define MAX_IFNAME_LEN          (32)
#define MAX_PORT                (65534)
#define MAX_CASTER_TTL          (255)
#define MAX_LOG_INTERVAL        (86400)
#define MAX_USER                (65534)
#define MAX_GROUP               (65534)
#define MIN_POOL_SIZE           (1000)
#define MAX_POOL_SIZE           (16777216)
#define MIN_HASH_SIZE           (1000)
#define MAX_HASH_SIZE           (16777216)
#define MIN_QUE_POOL_SIZE       (1000)
#define MAX_QUE_POOL_SIZE       (16777216)
#define MIN_QUE_HASH_SIZE       (1000)
#define MAX_QUE_HASH_SIZE       (16777216)
#define MIN_VNI                 (0)
#define MAX_VNI                 (16777215)
#define MAX_TIMEOUT             (65535)
#define MIN_SYNC_INTERVAL       (5000)
#define MAX_SYNC_INTERVAL       (3600000)
#define MIN_SYNC_TIMEOUT        (5000)
#define MAX_SYNC_TIMEOUT        (3600000)
#define MAX_SYNC_BUFFER         (1048576)
#define MAX_SNIPPER             (1)
#define MAX_DISPATCHER          (100)
#define MAX_CASTER              (100)
#define MAX_LOGGER              (1)
#define MAX_LISTENER            (100)
#define MAX_KICKER              (1)
#define MAX_TALKER              (100)

#ifndef ETHER_ADDR_LEN
#  define ETHER_ADDR_LEN        (6)
#endif

enum {
	FALSE = 0,
	TRUE  = 1,
};

enum {
	PROC_TYPE_INIT       = 0,
	PROC_TYPE_COMMAND    = 1,
	PROC_TYPE_LAUNCHER   = 2,
	PROC_TYPE_SNIPPER    = 3,
	PROC_TYPE_DISPATCHER = 4,
	PROC_TYPE_CASTER     = 5,
	PROC_TYPE_LOGGER     = 6,
	PROC_TYPE_LISTENER   = 7,
	PROC_TYPE_KICKER     = 8,
	PROC_TYPE_TALKER     = 9,
};

enum {
	OCTOPI_MAGIC         = 0xf1,
};

enum {
	OCTOPI_PROTO_IP4     = 0x41,
	OCTOPI_PROTO_IP6     = 0x61,
};

struct od_child {
	uint32_t type;
	pid_t pid;
};

#define NUM_COUNTER (4)
typedef union od_packet_counter {
	uint32_t packet[NUM_COUNTER];
	struct {
		uint32_t recv;
		uint32_t sent;
		uint32_t drop;
		uint32_t error;
	};
} COUNTER;

struct od_stat_set {
	COUNTER last;
	COUNTER count;
};

struct od_counter {
	time_t time;
	volatile struct od_stat_set child[];
};

typedef struct od_data {
	int proc_type;
	int child_id;
	int terminate;

	char *config_file;
	char *opt_rule_file;
	char *opt_queue_file;
	
	int debug;
	int dryrun;
	int quiet;
	int foreground;
	int no_syslog;

	char *rule_file;
	char *queue_file;
	char *pid_file;
	char *interface;
	ADDR *address;
	ADDR *sync_address;
	uint8_t mac[ETHER_ADDR_LEN];
	uint32_t vxlan_port;
	uint32_t relay_port;
	uint32_t sync_port;
	ADDR *multicast;
	uint32_t caster_ttl;

	int log_facility;
	uint32_t log_interval;
	uid_t user;
	gid_t group;
	uint32_t pool_size;
	uint32_t hash_size;
	uint32_t que_pool_size;
	uint32_t que_hash_size;
	char *secret;
	uint32_t timeout;
	uint32_t sync_timeout;
	uint32_t sync_interval;
	uint32_t sync_buffer;

	uint32_t snipper_procs;
	uint32_t dispatcher_procs;
	uint32_t caster_procs;
	uint32_t logger_procs;
	uint32_t listener_procs;
	uint32_t kicker_procs;
	uint32_t talker_procs;
	uint32_t opt_talker_procs;
	uint32_t num_childs;

	char pcap_filter[MAX_PCAP_FILTER];
	struct od_child *child;
	struct od_counter *counter;

	pcap_t *pcap;   /* Packet Capture receive by snipper*/
	int unix_out;   /* UNIX socket snet by snipper */
	int unix_in;    /* UNIX socket receive by dispatcher */
	int udp_out;    /* UDP socket sent by dispacther */
	int udp_in;     /* UPD socket receive by caster */
	int raw_out;    /* RAW socket sent by casetr */
	int sync_in;    /* TCP socket receive by listener */
	int sync_out;   /* TCP socket sent by talker */
} OD;

static inline void
inc_recv(OD *od)
{
	od->counter->child[od->child_id].count.recv ++;
}

static inline void
inc_sent(OD *od)
{
	od->counter->child[od->child_id].count.sent ++;
}

static inline void
inc_drop(OD *od)
{
	od->counter->child[od->child_id].count.drop ++;
}

static inline void
inc_error(OD *od)
{
	od->counter->child[od->child_id].count.error ++;
}

/* octopid.c / octopi.c */
void usage_and_exit(int);
void version_and_exit(int);
void finish_snipper(void);

/* signal.c */
void set_signal_blank(int);
void set_signal_hungup(int);
void set_signal_terminate(int);
void set_signal_debug_on(int);
void set_signal_debug_off(int);
void set_signal_ignore(int);
void block_signals(OD*);
void unblock_signals(OD*);

/* initialize */
void initialize(OD*);
int parse_args(OD*, int, char*[]);

/* readconf.c */
void readconf(OD*);

/* setup.c */
void setup_proc(OD*);
void close_extra_files(void);
void daemonize(OD*);
void setup_network(OD*);
void init_child(OD*);

/* snipper.c */
void snipper(OD*);

/* dispatcher.c */
void dispatcher(OD*);

/* caster.c */
void caster(OD*);

/* logger.c */
void logger(OD *);

/* listener.c */
void listener(OD *);

/* kicker.c */
void kicker(OD *);

#endif /* _OCTOPID_H */

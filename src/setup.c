/*
 *  setup.c
 *
 *  copyright (c) 2019-2021 HANATAKA Shinya
 *  copyright (c) 2019-2021 Internet Initiative Japan Inc.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <pcap.h>

#include "octopi.h"
#include "packet.h"
#include "logging.h"
#include "lpm.h"
#include "ioutil.h"

static cap_t
drop_capabilities(cap_t caps, uint32_t su)
{
	static cap_value_t target_cap[] = {
		CAP_NET_RAW, CAP_IPC_LOCK,
	};
	static cap_value_t su_cap[] = {
		CAP_SETUID, CAP_SETGID, CAP_SETPCAP,
	};
	int target_num = sizeof(target_cap) / sizeof(target_cap[0]);
	int su_num = sizeof(su_cap) / sizeof(su_cap[0]);

	/*
	 *  setup capabilities
	 */
	if (cap_clear(caps))
		return NULL;

	if (cap_set_flag(caps, CAP_EFFECTIVE, target_num, target_cap, CAP_SET))
		return NULL;
	if (cap_set_flag(caps, CAP_PERMITTED, target_num, target_cap, CAP_SET))
		return NULL;
	if (cap_set_flag(caps, CAP_EFFECTIVE, su_num, su_cap, su))
		return NULL;
	if (cap_set_flag(caps, CAP_PERMITTED, su_num, su_cap, su))
		return NULL;

	/*
	 *  update capabilities
	 */
	if (cap_set_proc(caps))
		return NULL;

	/*
	 *  change keep capabilities mode
	 */
	if (prctl(PR_SET_KEEPCAPS, su) < 0)
		return NULL;

	return caps;
}

void
change_user(OD *od)
{
        cap_t caps;

	/*
	 *  read current capabilities
	 */
	caps = cap_get_proc();
	if (!caps)
		error_exit("get capabilities failed: %s", strerror(errno));

	/*
	 *  drop unnecessary capabilities
	 */
	caps = drop_capabilities(caps, 1L);
	if (!caps)
		error_exit("drop capabilities failed: %s", strerror(errno));

	/*
	 *  change group and user
	 */
	if (setresgid(od->group, od->group, od->group))
		error_exit("change group failed: %s", strerror(errno));
	if (setresuid(od->user, od->user, od->user))
		error_exit("change user failed: %s", strerror(errno));

	/*
	 *  drop change user capabilities
	 */
	caps = drop_capabilities(caps, 0L);
	if (!caps)
		error_exit("drop change user capabilities failed: %s",
			   strerror(errno));
}


void
close_extra_files()
{
	int fd;
	int maxfd;
	
	/*
	 *  close all file descriptor
	 */
	maxfd = getdtablesize();
	for (fd = 3; fd < maxfd; fd++) {
		(void) close(fd);
	}
}

void
daemonize(OD *od)
{
	int pid;

	/*
	 *  setup cwd and umask
	 */
	(void) (chdir("/var/tmp") && chdir("/"));
	umask(022);

	/*
	 *  fork and start daemon
	 */
	pid = fork();
	if (pid < 0)
		error_exit("fork failed: %s", strerror(errno));
	else if (pid > 0)
		exit(0);

	/*
	 *  close standard I/O
	 */
	(void) close(STDIN_FILENO);
	(void) close(STDOUT_FILENO);
	(void) close(STDERR_FILENO);

	/*
	 *  switch to syslog
	 */
	if (!od->no_syslog)
		logging_start_syslog();
	logging_stop_stderr();

	/*
	 *  start new session and purge tty
	 */
	if (setsid() == (pid_t)-1)
		error_exit("setsid failed: %s", strerror(errno));

	/*
	 *  re-fork and split session master
	 */
	pid = fork();
	if (pid < 0)
		error_exit("fork failed: %s", strerror(errno));
	else if (pid > 0)
		exit(0);
}

/*
 *  make packet capture filter string
 */
static void
make_pcap_filter(OD *od)
{
	char addr[CIDR_STR_LEN];
	ADDR *p;
	size_t len = 0;

	/*
	 *  except self mac address
	 */
	xprintf(od->pcap_filter, &len, MAX_PCAP_FILTER,
		"not ether src %02x:%02x:%02x:%02x:%02x:%02x and ",
		od->mac[0], od->mac[1], od->mac[2],
		od->mac[3], od->mac[4], od->mac[5]);

	/*
	 *  multicast and vxlan port
	 */

#ifndef TCPDUMP_FIXED
	xprintf(od->pcap_filter, &len, MAX_PCAP_FILTER,
		"udp dst port %d", od->vxlan_port);
#else
	xprintf(od->pcap_filter, &len, MAX_PCAP_FILTER,
		"udp dst port %d and udp[8:2] = 0x800 & 0x800",
		od->vxlan_port);
#endif

	/*
	 *  TTL
	 */
	xprintf(od->pcap_filter, &len, MAX_PCAP_FILTER,
		" and ((ip and ip[8] > %u) or (ip6 and ip6[7] > %u))",
		od->caster_ttl, od->caster_ttl);

	/*
	 *  main multicast address
	 */
	cidr_to_str(od->multicast, addr);
	xprintf(od->pcap_filter, &len, MAX_PCAP_FILTER,
		" and multicast and ( dst net %s", addr);

	/*
	 *  extra multicast addresses
	 */
	for (p = od->multicast->next; p; p = p->next) {
		cidr_to_str(p, addr);
		if (xprintf(od->pcap_filter, &len, MAX_PCAP_FILTER,
			    " or dst net %s", addr))
			error_exit("Too many multicast address");
	}

	/*
	 *  closing
	 */
	if (xprintf(od->pcap_filter, &len, MAX_PCAP_FILTER, " )"))
		error_exit("Too many multicast address");

	debug("pcap_filter       %s", od->pcap_filter);
}

/*
 *  estimate main address of interface
 */
static int
addr_type(ADDR *a)
{
	enum {
		ADDR_UNKNOWN         = 0,
		ADDR_V6_NONE         = 1,
		ADDR_V4_NONE         = 2,
		ADDR_V6_LOOPBACK     = 3,
		ADDR_V4_LOOPBACK     = 4,
		ADDR_V6_MULTICAST    = 5,
		ADDR_V4_MULTICAST    = 6,
		ADDR_V6_LINK_LOCAL   = 7,
		ADDR_V6_SITE_LOCAL   = 8,
		ADDR_V6_GLOBAL       = 9,
		ADDR_V4_PRIVATE      = 10,
		ADDR_V4_GLOBAL       = 11,
	};

	if (a->af == AF_INET) {
		if (a->ipv4_addr == 0)
			return ADDR_V4_NONE;

		if ((a->ipv4_addr & 0xe0000000) == 0xe0000000)
			return ADDR_V4_MULTICAST;

		if ((a->ipv4_addr * 0xff000000) == 0x7f000000)
			return ADDR_V4_LOOPBACK;

		if ((a->ipv4_addr * 0xff000000) == 0x0a000000)
			return ADDR_V4_PRIVATE;

		if ((a->ipv4_addr * 0xfff00000) == 0xac100000)
			return ADDR_V4_PRIVATE;

		if ((a->ipv4_addr * 0xffff0000) == 0xc0a80000)
			return ADDR_V4_PRIVATE;

		return ADDR_V4_GLOBAL;
	}

	if (a->af == AF_INET6) {
		uint32_t pre = a->addr16[0];

		if (a->ipv6_addr == 0)
			return ADDR_V6_NONE;

		if (a->ipv6_addr == 1)
			return ADDR_V6_LOOPBACK;

		if ((pre & 0xff00) == 0xff00)
			return ADDR_V6_MULTICAST;

		if ((pre & 0xffc0) == 0xfe80)
			return ADDR_V6_LINK_LOCAL;

		if ((pre & 0xffc0) == 0xfec0)
			return ADDR_V6_SITE_LOCAL;

		return ADDR_V6_GLOBAL;
	}

	return ADDR_UNKNOWN;
}

static int
cmp_addr(ADDR *a, ADDR *b)
{
	if (a == NULL)
		return TRUE;

	if (addr_type(b) > addr_type(a))
		return TRUE;

	return FALSE;
}

static void
link_addr(ADDR **list, ADDR *a)
{
	ADDR *p;

	if (*list == NULL || cmp_addr(*list, a)) {
		a->next = *list;
		*list = a;
		return;
	}

	for (p = *list; p; p = p->next) {
		if (cmp_addr(p->next, a))
			break;
	}

	a->next = p->next;
	p->next = a;
}

static ADDR *
get_iface_addr(char *dev)
{
	struct ifaddrs *ifap;
        struct ifaddrs *p;
	ADDR *addr = NULL;

	/*
	 *  get interface list
	 */
	if (getifaddrs(&ifap) < 0)
		error_exit("getifaddr failed: %s", strerror(errno));

	/*
	 *  search suitable address
	 */
	for (p = ifap; p; p = p->ifa_next) {
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		ADDR *a;

		/*
		 *  check interface name
		 */
		if (strcmp(dev, p->ifa_name))
			continue;

		/*
		 *  allocate ADDR
		 */
		a = (ADDR *)malloc(sizeof(ADDR));
		if (a == NULL)
			crit_exit("out of memory ... aborted");
		memset(a, 0, sizeof(ADDR));

		/*
		 *  check protocol
		 */
		switch (p->ifa_addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in*) p->ifa_addr;
			a->af = AF_INET;
			a->ipv4_addr = ntohl(*(ip4_t*)(&sin->sin_addr));
			a->mask = 32;
			link_addr(&addr, a);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6*) p->ifa_addr;
			a->af = AF_INET6;
			a->ipv6_addr = ntohq(*(ip6_t*)(&sin6->sin6_addr));
			a->mask = 128;
			link_addr(&addr, a);
			break;
		}
	}
	freeifaddrs(ifap);

	if (addr == NULL)
		error_exit("address not found for %s", dev);

	{
		ADDR *a;
		char buf[CIDR_STR_LEN];
		int i = 1;

		for (a = addr; a; a = a->next)
			if (cidr_to_str(a, buf) == TRUE)
				debug("interface address[%d]  %s", i++, buf);
	}

	return addr;
}

static void
get_iface_mac(uint8_t *mac, char *dev)
{
	int fd;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0 || ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		error_exit("get mac failed: %s: %s", dev, strerror(errno));
	}
	close(fd);

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

static void
setup_packet_capture(OD *od)
{
	static char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;

	pcap = pcap_create(od->interface, errbuf);
	if (pcap == NULL)
		error_exit("pcap_create failed: %s", pcap_geterr(pcap));

	if (pcap_set_snaplen(pcap, MAX_PACKET_SIZE))
		error_exit("pcap_set_snaplen failed: %s", pcap_geterr(pcap));

	if (pcap_set_promisc(pcap, 1))
		error_exit("pcap_set_promisc failed: %s", pcap_geterr(pcap));

	if (pcap_set_timeout(pcap, 0))
		error_exit("pcap_set_timeout failed: %s", pcap_geterr(pcap));

	if (pcap_set_buffer_size(pcap, MAX_PACKET_SIZE * 1024))
		error_exit("pcap_set_buffer_size failed: %s",
			   pcap_geterr(pcap));

	if (pcap_set_immediate_mode(pcap, 1))
		error_exit("pcap_set_immediate_mode failed: %s",
		pcap_geterr(pcap));

	od->pcap = pcap;
}

static void
setup_unix_socket(OD *od)
{
	int fd[2];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd) < 0)
		error_exit("socketpair failed: %s", strerror(errno));

	od->unix_out = fd[0];
	od->unix_in  = fd[1];
}

static void
setup_udp_out_socket(OD *od)
{
	int udp_out;
	ADDR *address = od->address;	

	/*
	 *  relay sender socket
	 */
	udp_out = socket(address->af, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_out < 0)
		error_exit("socket(udp_out) failed: %s", strerror(errno));

	od->udp_out = udp_out;
}

static void
setup_udp_in_socket(OD *od)
{
	int udp_in;
	int reuse = 1;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr ad;
	} addr;
	ADDR *address = od->address;
	socklen_t len;

	/*
	 *  relay receiver socket
	 */
	udp_in = socket(address->af, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_in < 0)
		error_exit("socket(udp_in) failed: %s", strerror(errno));

	if (setsockopt(udp_in, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
		       sizeof reuse) < 0)
		error_exit("setsockopt(udp_in) failed: %s", strerror(errno));

	/*
	 *  bind address
	 */
	memset(&addr, 0, sizeof(addr));
	if (address->af == AF_INET) {
		addr.in.sin_family = AF_INET;
		addr.in.sin_port = htons(od->relay_port);
		addr.in.sin_addr.s_addr = htonl(address->ipv4_addr);
		len = sizeof(struct sockaddr_in);
	} else {
		addr.in6.sin6_family = AF_INET6;
		addr.in6.sin6_port = htons(od->relay_port);
		addr.in6.sin6_addr.s6_addr32[0]= htonl(address->addr32[3]);
		addr.in6.sin6_addr.s6_addr32[1]= htonl(address->addr32[2]);
		addr.in6.sin6_addr.s6_addr32[2]= htonl(address->addr32[1]);
		addr.in6.sin6_addr.s6_addr32[3]= htonl(address->addr32[0]);
		len = sizeof(struct sockaddr_in6);
	}
	if (bind(udp_in, &addr.ad, len))
		error_exit("bind(udp_in) failed: %s", strerror(errno));

	od->udp_in = udp_in;
}

static void
setup_raw_socket(OD *od)
{
	int raw_out;
	int bufsize = 0;
	struct ifreq ifr;
	struct sockaddr_ll sall;
	int on = 1;

	/*
	 *  create raw socket
	 */
	raw_out = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (raw_out < 0)
		error_exit("socket(raw_out) failed: %s", strerror(errno));

	/*
	 *  disable incoming buffer
	 */
	if (setsockopt(raw_out, SOL_SOCKET, SO_RCVBUF,
		       (char *)&bufsize, sizeof bufsize) < 0)
		error_exit("setsockopt(raw_out, SO_RCVBUF) failed: %s",
			   strerror(errno));

	/*
	 *  enable broadcast
	 */
	if (setsockopt(raw_out, SOL_SOCKET, SO_BROADCAST,
		       (char *)&on, sizeof(on)) < 0)
		error_exit("setsockopt(raw_out, SO_BROADCAST) failed: %s",
			   strerror(errno));

	/*
	 *  get iface index
	 */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, od->interface, sizeof(ifr.ifr_name) - 1);
	if (ioctl(raw_out, SIOCGIFINDEX, &ifr) < 0)
		error_exit("get iface id: failed: %s: %s",
			   od->interface, strerror(errno));

	/*
	 *  bind interface
	 */
	memset(&sall, 0, sizeof(sall));
	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(ETH_P_ALL);
	sall.sll_ifindex = ifr.ifr_ifindex;
	if (bind(raw_out, (struct sockaddr *) &sall, sizeof(sall)) < 0)
		error_exit("bind raw_out failed: %s: %s",
			   od->interface, strerror(errno));

	od->raw_out = raw_out;
}

static void
setup_sync_in_socket(OD *od)
{
	int sync_in;
	int reuse = 1;
	ADDR *address = od->sync_address;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr ad;
	} sa;
	socklen_t len;

	/*
	 *  server socket
	 */
	sync_in = socket(address->af, SOCK_STREAM, IPPROTO_TCP);
	if (sync_in < 0)
		error_exit("socket(sync) failed: %s", strerror(errno));

	if (setsockopt(sync_in, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
		       sizeof reuse) < 0)
		error_exit("setsockopt(sync) failed: %s", strerror(errno));

	/*
	 *  bind address
	 */
	memset(&sa, 0, sizeof(sa));
	if (address->af == AF_INET) {
		sa.in.sin_family = AF_INET;
		sa.in.sin_port = htons(od->sync_port);
		sa.in.sin_addr.s_addr = htonl(address->ipv4_addr);
		len = sizeof(struct sockaddr_in);
	} else {
		sa.in6.sin6_family = AF_INET6;
		sa.in6.sin6_port = htons(od->sync_port);
		sa.in6.sin6_addr.s6_addr32[0]= htonl(address->addr32[3]);
		sa.in6.sin6_addr.s6_addr32[1]= htonl(address->addr32[2]);
		sa.in6.sin6_addr.s6_addr32[2]= htonl(address->addr32[1]);
		sa.in6.sin6_addr.s6_addr32[3]= htonl(address->addr32[0]);
		len = sizeof(struct sockaddr_in6);
	}
	if (bind(sync_in, &sa.ad, len))
		error_exit("bind(udp_in) failed: %s", strerror(errno));

	od->sync_in = sync_in;
}

void
setup_proc(OD *od)
{
	/*
	 *  setup interface
	 */
	if (od->address == NULL)
		od->address = get_iface_addr(od->interface);
	get_iface_mac(od->mac, od->interface);

	/*
	 *  prepare pcap filter
	 */
	make_pcap_filter(od);

	/*
	 *  oepn rule
	 */
	LPM_open_or_init_rules(od->rule_file, O_RDONLY,
			       od->pool_size, od->hash_size);

	/*
	 *  change user
	 */
	change_user(od);
}

void
setup_network(OD *od)
{
	/*
	 *  setup network capture
	 */
	if (od->snipper_procs)
		setup_packet_capture(od);

	/*
	 *  setup I/O sockets
	 */
	if (od->caster_procs || od->dispatcher_procs)
		setup_unix_socket(od);

	if (od->dispatcher_procs > 0)
		setup_udp_out_socket(od);

	if (od->caster_procs > 0)
		setup_udp_in_socket(od);

	if (od->caster_procs > 0)
		setup_raw_socket(od);

	/*
	 *  setup SYNC socket
	 */
	if (od->listener_procs)
		setup_sync_in_socket(od);
}

static struct od_counter *
init_counter(OD *od)
{
	static struct od_counter *map;
	size_t size;

	size = sizeof(struct od_counter)
		+ sizeof(struct od_stat_set) * od->num_childs;
	map = (struct od_counter *)mmap(NULL, size, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (map == (struct od_counter *)MAP_FAILED)
		error_exit("mmap(counter) failed: %s", strerror(errno));

	return map;
}

void
init_child(OD *od)
{
	int c = 0;
	int i;

	od->num_childs
		= od->snipper_procs
		+ od->dispatcher_procs
		+ od->caster_procs
		+ od->logger_procs
		+ od->listener_procs
		+ od->kicker_procs;

	od->child = (struct od_child *)
		malloc(od->num_childs * sizeof(struct od_child));
	if (od->child == NULL)
		crit_exit("out of memory ... aborted");

	memset(od->child, 0, (od->num_childs * sizeof(struct od_child)));

	for (i = 0; i < od->snipper_procs; ++i)
		od->child[c++].type = PROC_TYPE_SNIPPER;

	for (i = 0; i < od->dispatcher_procs; ++i)
		od->child[c++].type = PROC_TYPE_DISPATCHER;

	for (i = 0; i < od->caster_procs; ++i)
		od->child[c++].type = PROC_TYPE_CASTER;

	for (i = 0; i < od->logger_procs; ++i)
		od->child[c++].type = PROC_TYPE_LOGGER;

	for (i = 0; i < od->listener_procs; ++i)
		od->child[c++].type = PROC_TYPE_LISTENER;

	for (i = 0; i < od->kicker_procs; ++i)
		od->child[c++].type = PROC_TYPE_KICKER;

	od->counter = init_counter(od);
}

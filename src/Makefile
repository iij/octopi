#
# Makefile for octopid and octopi
#

#
#  install dirctories
#
BASEDIR		= /opt/octopi
BINDIR  	= $(BASEDIR)/bin
SBINDIR 	= $(BASEDIR)/sbin
CONFDIR 	= $(BASEDIR)/etc
MANDIR  	= /usr/share/man
DATADIR 	= /var/octopi

#
#  compile options
#
DEFS		= -DCONFDIR=\"$(CONFDIR)\" -DDATADIR=\"$(DATADIR)\"
INC		=
CC		= gcc
WARN		= -Wall -Wno-stringop-truncation -Wno-format-truncation
CFLAGS		= -g -O3 $(WARN) $(DEFS) $(INC)
LDFLAGS 	=
TARGET		= octopid octopi

#
#  install options
#
INSTALL 	= /usr/bin/install
USER		= daemon
GROUP		= daemon
DIR_MODE	= -d -m 775 -o $(USER) -g $(GROUP)
BIN_MODE	= -m 755 -o $(USER) -g $(GROUP)
MAN_MODE        = -m 644 -o root -g root
DAT_MODE	= -m 644 -o $(USER) -g $(GROUP)


##########################################################################
#
#  libraries
#
LPM_LIB		= liblpm.a
LPM_HEADER	= lpm.h addrutil.h io_buffer.h proto.h
LPM_OBJS	= lpm.o lpm_ipv4.o lpm_ipv6.o lpm_output.o lpm_dump.o

QUE_LIB		= libque.a
QUE_HEADER	= que.h addrutil.h io_buffer.h proto.h
QUE_OBJS	= que.o que_output.o que_dump.o

RH		= rule.h octopi.h logging.h $(LPM_HEADER) $(QUE_HEADER)

#
#  programs
#
OCTOPID_HEADER  = octopi.h addrutil.h logging.h setproctitle.h
OCTOPID_LIBS	= $(LPM_LIB) $(QUE_LIB) -lcap -lpcap
OCTOPID_OBJS	= octopid.o signal.o initialize.o readconf.o setup.o \
	snipper.o dispatcher.o caster.o logger.o listener.o kicker.o \
	talker.o io_sync.o setproctitle.o token.o logging.o addrutil.o \
	ioutil.o pidfile.o rule_util.o rule_update.o io_buffer.o md5.o

OCTOPI_HEADER	= octopi.h addrutil.h logging.h command.h
OCTOPI_LIBS	= $(LPM_LIB) $(QUE_LIB)
OCTOPI_OBJS	= octopi.o initialize.o readconf.o signal.o setproctitle.o \
	command_init.o command_show.o command_list.o command_find.o \
	command_add.o command_delete.o command_move.o command_flush.o \
	command_pause.o command_unpause.o command_sync.o command_fsck.o \
	command_save.o command_restore.o command_update.o command_dump.o \
	command_queue.o command_queue_list.o command_queue_show.o \
	command_queue_init.o command_queue_add.o command_queue_delete.o \
	command_queue_enable.o command_queue_disable.o \
	command_queue_dump.o command_node.o command_node_list.o \
	command_node_add.o command_node_delete.o command_backup.o \
	command_backup_list.o command_backup_add.o command_backup_delete.o \
	command_acl.o command_acl_list.o command_acl_add.o \
	command_acl_delete.o command_rule.o rule_util.o rule_update.o \
	token.o logging.o addrutil.o ioutil.o io_buffer.o io_sync.o \
	kicker.o talker.o 

#
# rules
#
all: $(TARGET)

octopid: $(LPM_LIB) $(QUE_LIB) $(OCTOPID_OBJS)
	$(CC) $(LFLAGS) -o $@ $(OCTOPID_OBJS) $(OCTOPID_LIBS)

octopi: $(LPM_LIB) $(QUE_LIB) $(OCTOPI_OBJS)
	$(CC) $(LFLAGS) -o $@ $(OCTOPI_OBJS) $(OCTOPI_LIBS)

liblpm.a: $(LPM_OBJS)
	ar rcs $@ $(LPM_OBJS)

libque.a: $(QUE_OBJS)
	ar rcs $@ $(QUE_OBJS)

lpm.o:			lpm.c $(LPM_HEADER) lpm_internal.h ioutil.h logging.h
lpm_ipv4.o:		lpm_ipv4.c lpm_common.c $(LPM_HEADER) lpm_internal.h
lpm_ipv6.o:		lpm_ipv6.c lpm_common.c $(LPM_HEADER) lpm_internal.h
lpm_output.o:		lpm_output.c $(LPM_HEADER) lpm_internal.h logging.h
lpm_dump.o:		lpm_dump.c $(LPM_HEADER) lpm_internal.h

que.o:			que.c $(QUE_HEADER) que_internal.h ioutil.h logging.h
que_output.o:           que_output.c $(QUE_HEADER) que_internal.h lpm.h
que_dump.o:		que_dump.c $(QUE_HEADER) que_internal.h lpm.h

octopid.o:		octopid.c $(OCTOPID_HEADER)
snipper.o:		snipper.c $(OCTOPID_HEADER)
dispatcher.o:		dispatcher.c $(OCTOPID_HEADER) $(LPM_HEADER) packet.h
caster.o:		caster.c $(OCTOPID_HEADER) packet.h md5.h
logger.o:		logger.c $(OCTOPID_HEADER)
listener.o:		listener.c $(OCTOPID_HEADER) $(RH) io_sync.h
kicker.o:		kicker.c $(OCTOPID_HEADER) $(RH)
talker.o:		talker.c $(OCTOPID_HEADER) $(RH) ioutil.h io_sync.h
setproctitle.o:		setproctitle.c setproctitle.h
signal.o:		signal.c octopi.h addrutil.h logging.h
initialize.o:		initialize.c octopi.h addrutil.h logging.h token.h
readconf.o:		readconf.c octopi.h addrutil.h logging.h token.h
token.o:		token.c token.h addrutil.h logging.h
setup.o:		setup.c octopi.h $(LPM_HEADER) ioutil.h packet.h
addrutil.o:		addrutil.c addrutil.h
ioutil.o:		ioutil.c ioutil.h
io_buffer.o:		io_buffer.c io_buffer.h ioutil.h
logging.o:		logging.c logging.h ioutil.h
pidfile.o:		pidfile.c pidfile.h logging.h ioutil.h
md5.o:			md5.c md5.h
io_sync.o:		io_sync.c io_sync.h logging.h octopi.h
rule_util.o:		rule_util.c octopi.h $(RH)
rule_update.o:		rule_update.c octopi.h $(RH) token.h ioutil.h

octopi.o:		octopi.c $(OCTOPI_HEADER) setproctitle.h
command_rule.o:		command_rule.c $(OCTOPI_HEADER)
command_init.o:		command_init.c $(OCTOPI_HEADER) $(RH)
command_show.o:		command_show.c $(OCTOPI_HEADER) $(RH)
command_list.o:		command_list.c $(OCTOPI_HEADER) $(RH)
command_find.o:		command_find.c $(OCTOPI_HEADER) $(RH)
command_add.o:		command_add.c $(OCTOPI_HEADER) $(RH)
command_delete.o:	command_delete.c $(OCTOPI_HEADER) $(RH)
command_move.o:		command_move.c $(OCTOPI_HEADER) $(RH)
command_flush.o:	command_flush.c $(OCTOPI_HEADER) $(RH)
command_save.o:		command_save.c $(OCTOPI_HEADER) $(RH)
command_restore.o:	command_restore.c $(OCTOPI_HEADER) $(RH)
command_update.o:	command_update.c $(OCTOPI_HEADER) $(RH)
command_sync.o:		command_sync.c $(OCTOPI_HEADER) $(RH)
command_fsck.o:		command_fsck.c $(OCTOPI_HEADER) $(RH)
command_dump.o:		command_dump.c $(OCTOPI_HEADER) $(RH)
command_pause.o:	command_pause.c $(OCTOPI_HEADER) $(RH)
command_unpause.o:	command_unpause.c $(OCTOPI_HEADER) $(RH)
command_queue.o:	command_queue.c $(OCTOPI_HEADER)
command_queue_list.o:	command_queue_list.c $(OCTOPI_HEADER) $(RH)
command_queue_show.o:	command_queue_show.c $(OCTOPI_HEADER) $(RH)
command_queue_init.o:	command_queue_init.c $(OCTOPI_HEADER) $(RH)
command_queue_add.o:	command_queue_add.c $(OCTOPI_HEADER) $(RH)
command_queue_delete.o:	command_queue_delete.c $(OCTOPI_HEADER) $(RH)
command_queue_enable.o:	command_queue_enable.c $(OCTOPI_HEADER) $(RH)
command_queue_disable.o:	command_queue_disable.c $(OCTOPI_HEADER) $(RH)
command_queue_dump.o:	command_queue_dump.c $(OCTOPI_HEADER) $(RH)
command_queue_sync.o:	command_queue_sync.c $(OCTOPI_HEADER) $(RH)
command_node.o:		command_node.c $(OCTOPI_HEADER)
command_node_list.o:	command_node_list.c $(OCTOPI_HEADER) $(RH)
command_node_add.o:	command_node_add.c $(OCTOPI_HEADER) $(RH)
command_node_delete.o:	command_node_delete.c $(OCTOPI_HEADER) $(RH)
command_backup.o:	command_backup.c $(OCTOPI_HEADER)
command_backup_list.o:	command_backup_list.c $(OCTOPI_HEADER) $(RH)
command_backup_add.o:	command_backup_add.c $(OCTOPI_HEADER) $(RH)
command_backup_delete.o:	command_backup_delete.c $(OCTOPI_HEADER) $(RH)
command_acl.o:		command_acl.c $(OCTOPI_HEADER)
command_acl_list.o:	command_acl_list.c $(OCTOPI_HEADER) $(RH)
command_acl_add.o:	command_acl_add.c $(OCTOPI_HEADER) $(RH)
command_acl_delete.o:	command_acl_delete.c $(OCTOPI_HEADER) $(RH)

install: $(TARGET)
	$(INSTALL) $(DIR_MODE) $(BASEDIR)
	$(INSTALL) $(DIR_MODE) $(BINDIR)
	$(INSTALL) $(DIR_MODE) $(SBINDIR)
	$(INSTALL) $(DIR_MODE) $(CONFDIR)
	$(INSTALL) $(DIR_MODE) $(DATADIR)
	$(INSTALL) ${BIN_MODE} octopid $(SBINDIR)
	$(INSTALL) ${BIN_MODE} octopi $(BINDIR)
	$(INSTALL) $(MAN_MODE) ../man/octopid.8 $(MANDIR)/man8
	$(INSTALL) $(MAN_MODE) ../man/octopi.1 $(MANDIR)/man1
	$(INSTALL) $(MAN_MODE) ../man/octopi.conf.5 $(MANDIR)/man5
	$(INSTALL) ${DAT_MODE} octopi.conf-example $(BASEDIR)/etc

clean:
	-rm -f core $(TARGET) $(LPM_LIB) $(QUE_LIB) *.o *~

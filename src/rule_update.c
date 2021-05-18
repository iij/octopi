/*
 *  rule_update.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "octopi.h"
#include "addrutil.h"
#include "logging.h"
#include "lpm.h"
#include "rule.h"
#include "token.h"
#include "ioutil.h"
#include "io_buffer.h"

enum {
	UPDATE_INIT   = 0,
	UPDATE_RULE   = 1,
	UPDATE_FINISH = 2,
};

struct update_data {
	int      linenum;
	int      mode;
	char     *pos;
	uint32_t vni;
	uint8_t  proto;
	QRELAY   *qr;
	int      error;
	char     *peer;
};

static void
action_rule(OD *od, struct update_data *u)
{
	char *token;
	char *errmsg;

	/*
	 *  check mode
	 */
	if (u->mode != UPDATE_INIT) {
		error("%s: line %d: multiple rules", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  read vni
	 */
	token = get_token(&u->pos);
	if (token == NULL) {
		error("%s: line %d: rule needs vni", u->peer, u->linenum);
		u->error = 1;
		return;
	}
	if (conv_vni(token, &u->vni, &errmsg) == FALSE) {
		error("%s: line %d: %s", u->peer, u->linenum, errmsg);
		u->error = 1;
		return;
	}
	if (u->vni == VNI_ALL) {
		error("%s: line %d: vni must be a number or \"any\"",
		      u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  check trailing garbage
	 */
	if (get_token(&u->pos) != NULL) {
		error("%s: line %d: syntax error", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  flush work tree
	 */
	if (!od->dryrun)
		LPM_flush_rule(VNI_WORK, PROTO_ALL);

	u->mode = UPDATE_RULE;
}

static void
action_target(OD *od, struct update_data *u, char *target)
{
	char *token;
	int count = 0;
	npos_t node = 0;
	char *errmsg;

	/*
	 *  check mode
	 */
	if (u->mode == UPDATE_INIT) {
		error("%s: line %d: syntax error", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  read target
	 */
	if (conv_target(target, &node, od->dryrun, &errmsg) == FALSE) {
		error("%s: line %d: %s", u->peer, u->linenum, errmsg);
		u->error = 1;
		return;
	}

	/*
	 *  read relay list
	 */
	while ((token = get_token(&u->pos))) {
		if (conv_relay(node, token, od->dryrun, &errmsg) == FALSE) {
			LPM_unset_access_node(node);

			error("%s: line %d: %s", u->peer, u->linenum, errmsg);
			u->error = 1;
			return;
		}
		count ++;
	}

	/*
	 *  check number of relays
	 */
	if (count == 0) {
		LPM_unset_access_node(node);

		error("%s: line %d: needs relay", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  add rule to work tree
	 */
	if (!od->dryrun)
		LPM_add_rule(VNI_WORK, node);
}

static void
action_commit(OD *od, struct update_data *u)
{
	/*
	 *  check mode
	 */
	if (u->mode == UPDATE_INIT) {
		error("%s: line %d: commit without rule", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  check trailing garbage
	 */
	if (get_token(&u->pos) != NULL) {
		error("%s: line %d: syntax error", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  update rule and queue
	 */
	if (!od->dryrun) {
		/* get previous relay */
		QRELAY *qr = init_qrelay(od);
		get_qrelay(od, qr, u->vni);

		/*
		 *  update
		 */
		LPM_update_rule(VNI_WORK, u->vni, u->proto);

		/* get later relay and push */
		get_qrelay(od, qr, u->vni);
		push_qrelay(od, qr, u->vni);

		/* logging */
		if (od->proc_type == PROC_TYPE_LISTENER) {
			if (u->vni == VNI_ANY)
				debug("%s: vni any updated", u->peer);
			else
				debug("%s: vni %u updated", u->peer, u->vni);
		}
	}

	u->mode = UPDATE_INIT;
}

static void
action_abort(OD *od, struct update_data *u)
{
	/*
	 *  check mode
	 */
	if (u->mode == UPDATE_INIT) {
		error("%s: line %d: abort without rule", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  check trailing garbage
	 */
	if (get_token(&u->pos) != NULL) {
		error("%s: line %d: syntax error", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  abort
	 */
	if (!od->dryrun)
		LPM_flush_rule(VNI_WORK, PROTO_ALL);

	u->mode = UPDATE_INIT;
}

static void
action_end(OD *od, struct update_data *u)
{
	/*
	 *  check mode
	 */
	if (u->mode != UPDATE_INIT) {
		error("%s: line %d: end within rule", u->peer, u->linenum);

		LPM_flush_rule(VNI_WORK, PROTO_ALL);
		u->error = 1;
		return;
	}

	/*
	 *  check trailing garbage
	 */
	if (get_token(&u->pos) != NULL) {
		error("%s: line %d: syntax error", u->peer, u->linenum);
		u->error = 1;
		return;
	}

	/*
	 *  end
	 */
	u->mode = UPDATE_FINISH;
}

int
update_rules(OD *od, int fd, uint8_t proto, int restore, char *peer)
{
	struct update_data udat;
	IOBUF *buf;
	int ret;
	char peer_buf[IP_STR_LEN + 16];

	/*
	 *  initialize update data
	 */
	udat.mode    = UPDATE_INIT;
	udat.pos     = NULL;
	udat.proto   = proto;
	udat.linenum = 0;
	udat.qr      = NULL;
	udat.error   = 0;
	if (peer == NULL) {
		udat.peer = "stdin";
	} else {
		size_t pos = 0;
		xprintf(peer_buf, &pos, IP_STR_LEN + 16, "sync from %s", peer);
		udat.peer = peer_buf;
	}

	/*
	 *  initialize buffer
	 */
	buf = init_iobuf(od->sync_buffer, SYNC_IO_SIZE);
	if (buf == NULL)
		crit_exit("out of memory ... aborted");
	set_fd_iobuf(buf, fd);

	/*
	 *  fill buffer
	 */
	do {
		if (od->terminate)
			return FALSE;

		ret = fill_iobuf(buf, od->sync_timeout, "end");
		if (ret == IO_FAIL) {
			error("read failed: %s", strerror(errno));
			return FALSE;
		}
	} while (ret == IO_IRUPT);

	/*
	 *  open rule
	 */
	open_rule_file(od, O_RDWR);

	/*
	 *  prepare restore
	 */
	if (restore && !od->dryrun) {
		udat.qr = init_qrelay(od);
		get_qrelay(od, udat.qr, VNI_ALL);
		LPM_restore_start(proto);
	}

	/*
	 *  process update
	 */
	while (udat.error == 0 && udat.mode != UPDATE_FINISH) {
		char *token;

		/*
		 *  get next line
		 */
		udat.pos = (char*) read_iobuf(buf);
		if (udat.pos == NULL) {
			if (udat.mode == UPDATE_INIT)
				udat.mode = UPDATE_FINISH;
			break;
		}
		udat.linenum ++;

		/*
		 *  get token
		 */
		token = get_token(&udat.pos);
		if (token == NULL)
			continue;

		/*
		 *  actions
		 */
		if (strcasecmp(token, "end") == 0) {
			action_end(od, &udat);
		} else if (strcasecmp(token, "rule") == 0) {
			action_rule(od, &udat);
		} else if (strcasecmp(token, "commit") == 0) {
			action_commit(od, &udat);
		} else if (strcasecmp(token, "abort") == 0) {
			action_abort(od, &udat);
		} else {
			action_target(od, &udat, token);
		}
	}

	if (udat.mode == UPDATE_RULE) {
		if (!udat.error) {
			error("line %d: data ran out", udat.linenum);
			udat.error = 1;
		}
		if (!od->dryrun)
			LPM_flush_rule(VNI_WORK, PROTO_ALL);
	}

	if (udat.error) {
		if (udat.qr) {
			LPM_restore_abort(proto);
			free_qrelay(od, udat.qr);
		}
		sync_rule_file(od);
		close_rule_file(od);

		return FALSE;
	}

	/*
	 *  delete rule which is not restored
	 */
	if (udat.qr) {
		LPM_restore_finish(proto);

		/* all queue sync */
		get_qrelay(od, udat.qr, VNI_ALL);
		push_qrelay(od, udat.qr, VNI_ALL);

		/* logging */
		if (od->proc_type == PROC_TYPE_LISTENER)
			debug("%s: restore finished", udat.peer);
	}

	/*
	 *  close rule
	 */
	sync_rule_file(od);
	close_rule_file(od);

	return TRUE;
}

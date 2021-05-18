/*
 *  token.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>

#include "logging.h"
#include "addrutil.h"
#include "token.h"

enum {
	FALSE = 0,
	TRUE  = 1,
};


/*
 *  user-ID and group-ID
 */
int
str_to_uid(char *name, uid_t *user, uint32_t max)
{
	char buf[1024];
	struct passwd pw;
	struct passwd *rst;
	uint32_t uid;

	if (str_to_uint32(name, &uid) == TRUE) {
		if (uid > max)
			return FALSE;
		*user = (uid_t) uid;
		return TRUE;
	} else if (!getpwnam_r(name, &pw, buf, 1024, &rst)) {
		*user = pw.pw_uid;
		return TRUE;
	}

	return FALSE;
}

int
str_to_gid(char *name, gid_t *group, uint32_t max)
{
	char buf[1024];
	struct group gr;
	struct group *rst;
	uint32_t gid;

	if (str_to_uint32(name, &gid) == TRUE) {
		if (gid > max)
			return FALSE;
		*group = (gid_t) gid;
		return TRUE;
	} else if (!getgrnam_r(name, &gr, buf, 1024, &rst)) {
		*group = gr.gr_gid;
		return TRUE;
	}

	return FALSE;
}


/*
 *  cut token from string
 */
inline void *
iseol(char c)
{
	return memchr("#\r\n\0", c, 4);
}

char *
get_token(char **str)
{
	char *head;
	char *tail;

	/*
	 *  check null pointer
	 */
	if (*str == NULL)
		return NULL;

	/*
	 *  skip leading white speaces
	 */
	for (head = *str; isspace((int)*head); ++ head);

	/*
	 *  check end of line
	 */
	if (iseol(*head)) {
		*str = NULL;
		return NULL;
	}

	/*
	 *  get next token
	 */
	 for (tail = head; !isspace((int)*tail) && !iseol(*tail); ++ tail);

	 if  (iseol(*tail))
		 *str = NULL;
	 else
		 *str = tail + 1;

	 /*
	  *  terminate word
	  */
	 *tail = '\0';

	 return head;
}

char *
read_one_token(char *fname, int lnum, char *tag, char **pcur)
{
	char *token;

	/*
	 *  get next token
	 */
	token = get_token(pcur);
	if (token == NULL)
		error_exit("%s:%d %s needs argument", fname, lnum, tag);

	/*
	 *  check next argument
	 */
	if (get_token(pcur) != NULL)
		error_exit("%s:%d %s needs just one argument",
			   fname, lnum, tag);

	return token;
}

/*
 *  parse token
 */
int
read_debug(char *fname, int lnum, char *tag, char **pcur)
{
	if (get_token(pcur) != NULL)
		error_exit("%s:%d %s needs no argument", fname, lnum, tag);

	debug_on();
	return 1;
}

char *
read_str(char *fname, int lnum, char *tag, char **pcur,
	 uint32_t min, uint32_t max)
{
	char *token;
	int len;
	char *str;

	/*
	 *  get next token
	 */
	token = read_one_token(fname, lnum, tag, pcur);

	/*
	 *  check length
	 */
	len = strlen(token);
	if (len < min)
		error_exit("%s:%d %s argument is too short (minimum %u)",
			   fname, lnum, tag, min);

	if (max != 0 && len > max)
		error_exit("%s:%d %s argument is too log (maximum %u)",
			   fname, lnum, tag, max);

	str = strdup(token);
	if (str == NULL)
		crit_exit("out of memory ... aborted");

	return str;
}

uint32_t
read_num(char *fname, int lnum, char *tag, char **pcur,
	 uint32_t min, uint32_t max)
{
	char *token;
        char *end;
        uint32_t num;

	/*
	 *  get next token
	 */
	token = read_one_token(fname, lnum, tag, pcur);

	/*
	 *  convert to number
	 */
	num = strtoul(token, &end, 0);
	if (*end != '\0')
		error_exit("%s:%d %s needs a number", fname, lnum, tag);

	/*
	 *  check range
	 */
	if (num < min)
		error_exit("%s:%d %s argument %s is too small (minimum %u)",
			   fname, lnum, tag, token, min);

	if (max != 0 && num > max)
		error_exit("%s:%d %s %s argument is too large (maximum %u)",
			   fname, lnum, tag, token, max);

	return num;
}

int
read_log_facility(char *fname, int lnum, char *tag, char **pcur)
{
	static struct _facility {
		char *name;
		int val;
	} *p, facility_list[] = {
		{ "kern",     LOG_KERN },
		{ "user",     LOG_USER },
		{ "mail",     LOG_MAIL },
		{ "daemon",   LOG_DAEMON },
		{ "auth",     LOG_AUTH },
		{ "syslog",   LOG_SYSLOG },
		{ "lpr",      LOG_LPR },
		{ "news",     LOG_NEWS },
		{ "uucp",     LOG_UUCP },
		{ "cron",     LOG_CRON },
		{ "authpriv", LOG_AUTHPRIV },
		{ "ftp",      LOG_FTP },
		{ "local0",   LOG_LOCAL0 },
		{ "local1",   LOG_LOCAL1 },
		{ "local2",   LOG_LOCAL2 },
		{ "local3",   LOG_LOCAL3 },
		{ "local4",   LOG_LOCAL4 },
		{ "local5",   LOG_LOCAL5 },
		{ "local6",   LOG_LOCAL6 },
		{ "local7",   LOG_LOCAL7 },
		{ NULL,       -1 },
	};
	char *token;

	/*
	 *  get next token
	 */
	token = read_one_token(fname, lnum, tag, pcur);

	/*
	 *  search facility
	 */
	for (p = facility_list; p->name; ++ p)
		if (strcasecmp(p->name, token) == 0)
			return p->val;

	/*
	 *  no match
	 */
	error_exit("%s:%d %s %s is not defined", fname, lnum, tag, token);

	/* NOTREACHED */
	return 0;
}

uid_t
read_user(char *fname, int lnum, char *tag, char **pcur, uint32_t max)
{
	char *token;
	uid_t uid;

	/*
	 *  get next token
	 */
	token = read_one_token(fname, lnum, tag, pcur);

	/*
	 *  convert to user-id
	 */
	if (str_to_uid(token, &uid, max) == FALSE)
		error_exit("%s:%d %s user %s is unknown",
			   fname, lnum, tag, token);

	return uid;
}

gid_t
read_group(char *fname, int lnum, char *tag, char **pcur, uint32_t max)
{
	char *token;
	gid_t gid;

	/*
	 *  get next token
	 */
	token = read_one_token(fname, lnum, tag, pcur);

	/*
	 *  convert to group-id
	 */
	if (str_to_gid(token, &gid, max) == FALSE)
		error_exit("%s:%d %s group %s is unknown",
			   fname, lnum, tag, token);

	return gid;
}

ADDR *
read_cidr(char *fname, int lnum, char *tag, char **pcur)
{
	char *token;
	ADDR *address = NULL;
	ADDR **tail = &address;

	while ((token = get_token(pcur))) {
		ADDR a;

		if (str_to_cidr(token, &a) == FALSE)
			error_exit("%s:%d %s %s is invalid",
				   fname, lnum, tag, token);
		*tail = (ADDR *) malloc(sizeof(ADDR));
		if (*tail == NULL)
			crit_exit("out of memory ... aborted");

		memcpy(*tail, &a, sizeof(ADDR));
		tail = &(*tail)->next;
	}

	if (address == NULL)
		error_exit("%s:%d %s needs arguments", fname, lnum, tag);

	return address;
}

ADDR *
read_addr(char *fname, int lnum, char *tag, char **pcur)
{
	char *token;
	ADDR *addr;

	/* read token */
	token = read_one_token(fname, lnum, tag, pcur);	
	if (token == NULL)
		error_exit("%s:%d %s needs arguments", fname, lnum, tag);

	/* convert address */
	addr = (ADDR *) malloc(sizeof(ADDR));
	if (addr == NULL)
		crit_exit("out of memory ... aborted");	
	if (str_to_addr(token, addr) == FALSE)
		error_exit("%s:%d %s %s is invalid", fname, lnum, tag, token);

	return addr;
}

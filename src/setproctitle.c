/*
 *  setproctitle.c
 *
 *  copyright (c) 2019-2020 HANATAKA Shinya
 *  copyright (c) 2019-2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "setproctitle.h"

static const char *arg0_bak = NULL;
static char *arg_buf = NULL;
static int arg_buf_len = 0;

void
setproctitle_init(int argc, char *argv[], char *envp[])
{
        int envc;
	int i;
	int len;
	char **envcopy;
	char *arg_end;

	/*
	 *  check argument
	 */
	if (argc < 0)
		return;
	if (argv[0] == NULL)
		return;

	/*
	 *  count argc
	 */
	for (i = 0; envp[i];  ++ i);
	envc = i;

	/*
	 *  check last
	 */
	if (envc > 0)
		arg_end = envp[envc - 1] + strlen(envp[envc - 1]) + 1;
	else
		arg_end = argv[argc - 1] + strlen(argv[argc - 1]) + 1;

	/*
	 *  backup argv
	 */
	arg0_bak = strdup(argv[0]);
	if (arg0_bak == NULL)
		_exit(255);
	arg_buf = argv[0];
	arg_buf_len = arg_end - arg_buf;

	/*
	 *  copy environments
	 */
	len = sizeof(char *) * (envc + 1);
        envcopy = malloc(len);
        if (envcopy == NULL)
		_exit(255);
	memcpy(envcopy, envp, len);
	if (clearenv())
		_exit(255);

        for (i = 0; i < envc; i ++) {
		char *p = strchr(envcopy[i], '=');
		if (p == NULL)
			continue;
		*p = 0;
		if (setenv(envcopy[0], p + 1, 1))
			_exit(255);
	}
	free(envcopy);

	/*
	 *  copy arguments
	 */
	for (i = 0; i < argc || (i >= argc && argv[i]); ++ i) {
		if (argv[i]) {
			argv[i] = strdup(argv[i]);
			if (argv[i] == NULL)
				_exit(255);
		}
	}
}

void
setproctitle(const char *prog)
{
        size_t len;

	/*
	 *  check initialized
	 */
	if (!arg_buf || arg_buf_len <= 0)
                return;

	/*
	 *  check revert
	 */
	if (prog == NULL)
		prog = arg0_bak;

	/*
	 *  check length
	 */
	len = strlen(prog);
	if (len > arg_buf_len - 1)
		len = arg_buf_len - 1;

	/*
	 *  set proctitle
	 */
	memset(arg_buf, 0, arg_buf_len);
        memcpy(arg_buf, prog, len);
}

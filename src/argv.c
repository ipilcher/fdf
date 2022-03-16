// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	argv.c - Command-line parsing
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

#include <stdio.h>

typedef int (*fdf_parse_fn)(char **const argv, const int i, const _Bool flag);

_Bool fdf_debug = 0;
_Bool fdf_pktlog = 0;
_Bool fdf_use_syslog = 0;
const char *fdf_cfg_json_name = "/etc/fdf-config.json";

static int fdf_parse_output(char **const argv __attribute__((unused)),
			    const int i __attribute__((unused)),
			    const _Bool flag)
{
	static _Bool set;

	if (set)
		FDF_FATAL("Log destination (-l or -e) specified twice");

	fdf_use_syslog = flag;
	set = 1;

	return 0;
}

static int fdf_parse_debug(char **const argv __attribute__((unused)),
			   const int i __attribute__((unused)),
			   const _Bool flag __attribute__((unused)))
{
	static _Bool set;

	if (set)
		FDF_FATAL("Debug output (-d) specified twice");

	fdf_debug = 1;
	set = 1;

	return 0;
}

static int fdf_parse_pktlog(char **const argv __attribute__((unused)),
			    const int i __attribute__((unused)),
			    const _Bool flag __attribute__((unused)))
{
	static _Bool set;

	if (set)
		FDF_FATAL("Packet logging (-p) specified twice");

	fdf_pktlog = 1;
	set = 1;

	return 0;
}

static int fdf_parse_cfg_name(char **const argv, const int i,
			      const _Bool flag __attribute__((unused)))
{
	static _Bool set;

	if (set)
		FDF_FATAL("Configuration file (-c) specified twice");

	if (argv[i + 1] == NULL)
		FDF_FATAL("Configuration file (-c) requires file name");

	fdf_cfg_json_name = argv[i + 1];
	set = 1;

	return 1;
}

static int fdf_parse_help(char **const argv __attribute__((unused)),
			  const int i __attribute__((unused)),
			  const _Bool flag __attribute__((unused)))
{
	printf("%s options:\n"
			"    -l | --syslog:  log messages to syslog\n"
			"    -e | --stderr:  log messages to stderr\n"
			"    -d | --debug: log debug level messages\n"
			"    -p | --pktlog: enable verbose packet logging\n"
			"    -c | --config: specify configuration file\n"
			"    -h | --help: show this message and exit\n",
		argv[0]);

	exit(EXIT_SUCCESS);
}

static _Bool fdf_streq(const char *const a, const char *const b)
{
	return strcmp(a, b) == 0;
}

void fdf_parse_argv(const int argc, char **const argv)
{
	static const struct {
		const char	*short_opt;
		const char	*long_opt;
		fdf_parse_fn	parse_fn;
		_Bool		flag;
	}
	opts[] = {
		{ "-l", "--syslog", fdf_parse_output, 1 },
		{ "-e", "--stderr", fdf_parse_output, 0 },
		{ "-d", "--debug", fdf_parse_debug, 0 },
		{ "-p", "--pktlog", fdf_parse_pktlog, 0 },
		{ "-h", "--help", fdf_parse_help, 0 },
		{ "-c", "--config", fdf_parse_cfg_name, 0 },
		{ NULL }
	};

	int i;
	unsigned j;
	const char *arg;

	for (i = 1; i < argc; ++i) {

		arg = argv[i];

		for (j = 0; opts[j].short_opt != NULL; ++j) {

			if (fdf_streq(arg, opts[j].short_opt)
					|| fdf_streq(arg, opts[j].long_opt)) {

				i += opts[j].parse_fn(argv, i, opts[j].flag);
				break;
			}
		}

		if (opts[j].short_opt == NULL)
			FDF_FATAL("Unknown option: %s", argv[i]);
	}
}

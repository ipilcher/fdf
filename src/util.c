// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	util.c - Miscellaneous functions
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

#include <stdarg.h>
#include <stdio.h>

volatile sig_atomic_t fdf_exit_flag = 0;

static void fdf_catch_signal(const int signum __attribute__((unused)))
{
	fdf_exit_flag = 1;
}

void fdf_signal_setup(sigset_t *const oldmask)
{
	struct sigaction sa;
	sigset_t mask;

	if (sigemptyset(&mask) != 0)
		FDF_PFATAL("sigemptyset");
	if (sigaddset(&mask, SIGTERM) != 0)
		FDF_PFATAL("sigaddset(SIGTERM)");
	if (sigaddset(&mask, SIGINT) != 0)
		FDF_PFATAL("sigaddset(SIGINT)");

	sa.sa_handler = fdf_catch_signal;
	sa.sa_mask = mask;
	sa.sa_flags = SA_RESETHAND;

	if (sigprocmask(SIG_BLOCK, &mask, oldmask) != 0)
		FDF_PFATAL("sigprocmask");

	if (sigaction(SIGTERM, &sa, NULL) != 0)
		FDF_PFATAL("sigaction(SIGTERM)");
	if (sigaction(SIGINT, &sa, NULL) != 0)
		FDF_PFATAL("sigaction(SIGINT)");
}
void *fdf_zalloc(const size_t size, const char *const file, const int line)
{
	void *result;

	if ((result = calloc(1, size)) == NULL) {
		fdf_log(LOG_ERR, "ERR: %s:%d: Memory allocation failure",
			file, line);
		exit(EXIT_FAILURE);
	}

	return result;
}

void fdf_log(const int level, const char *const format, ...)
{
	va_list ap;
	size_t fmt_len;

	va_start(ap, format);

	if (fdf_use_syslog) {
		vsyslog(level, format, ap);
	}
	else {
		vfprintf(stderr, format, ap);
		fmt_len = strlen(format);
		if (fmt_len > 0 && format[fmt_len - 1] != '\n')
			fputc('\n', stderr);
	}

	va_end(ap);
}

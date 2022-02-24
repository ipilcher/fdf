// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <unistd.h>

static void fdf_early_setup(void)
{
	fdf_use_syslog = !isatty(STDERR_FILENO);
	setlinebuf(stderr);
}

static void fdf_cleanup(const int epfd)
{
	fdf_free_listeners(epfd);
	fdf_free_matches();
	fdf_free_netifs();
	fdf_free_filters();
	fdf_sender_close();

	if (close(epfd) < 0)
		FDF_PFATAL("close");
}

int main(int argc, char **const argv)
{
	struct epoll_event events[FDF_EPOLL_EVENT_MAX];
	sigset_t epmask;
	int epfd, ready, i;

	fdf_early_setup();
	fdf_parse_argv(argc, argv);
	fdf_parse_config();
	epfd = fdf_init_listeners();
	fdf_sender_init();

	fdf_signal_setup(&epmask);  /* blocks SIGINT & SIGTERM */

	while (fdf_exit_flag == 0) {

		ready = epoll_pwait(epfd, events, FDF_EPOLL_EVENT_MAX,
				    -1, &epmask);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			FDF_PFATAL("epoll_wait");
		}

		for (i = 0; i < ready; ++i) {
			if (events[i].events & EPOLLIN)
				fdf_process(events[i].data.ptr);
		}
	}

	fdf_cleanup(epfd);
	exit(EXIT_SUCCESS);
}

// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	listen.c - Listener sockets
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>

static struct fdf_listener *fdf_listeners = NULL;

void fdf_listener_add(struct fdf_listener *const new)
{
	new->next = fdf_listeners;
	fdf_listeners = new;
}

void fdf_free_listeners(const int epfd)
{
	struct fdf_listener *lstnr, *next;

	lstnr = fdf_listeners;

	while (lstnr != NULL) {

		if (epoll_ctl(epfd, EPOLL_CTL_DEL, lstnr->fd, NULL) != 0)
			FDF_PFATAL("EPOLL_CTL_DEL");

		if (close(lstnr->fd) < 0)
			FDF_PFATAL("close");

		next = lstnr->next;
		free(lstnr);
		lstnr = next;
	}

	fdf_listeners = NULL;
}

static void fdf_listen_mcast(const struct fdf_listener *const lstnr)
{
	static const int opt = 0;

	struct ip_mreqn imr;
	int err;

	err = setsockopt(lstnr->fd, IPPROTO_IP, IP_MULTICAST_LOOP,
			 &opt, sizeof opt);
	if (err) {
		FDF_FATAL("Failed to set IP_MULTICAST_LOOP option for "
					"listener socket (%s:%s): %m",
			  lstnr->listen_netif->name, lstnr->match->name);
	}

	imr.imr_multiaddr = lstnr->match->sa.sin.sin_addr;
	imr.imr_address.s_addr = htonl(INADDR_ANY);  /* valgrind warning */
	imr.imr_ifindex = lstnr->listen_netif->index;

	err = setsockopt(lstnr->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			 &imr, sizeof imr);
	if (err) {
		FDF_FATAL("Failed to set IP_ADD_MEMBERSHIP option for "
					"listener socket (%s:%s): %m",
			  lstnr->listen_netif->name, lstnr->match->name);
	}
}

static void fdf_listen_socket(struct fdf_listener *const lstnr)
{
	static const int opt = 1;

	int err;

	lstnr->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if (lstnr->fd < 0) {
		FDF_FATAL("Failed to create listener socket (%s:%s): %m",
			  lstnr->listen_netif->name, lstnr->match->name);
	}

	err = setsockopt(lstnr->fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof opt);
	if (err) {
		FDF_FATAL("Failed to set SO_REUSEPORT option for "
					"listener socket (%s:%s): %m",
			  lstnr->listen_netif->name, lstnr->match->name);
	}

	err = bind(lstnr->fd, &lstnr->match->sa.sa,
		   sizeof lstnr->match->sa.sin);
	if (err) {
		FDF_FATAL("Failed to bind listener socket (%s:%s) to "
					"address %s:%" PRIu16 ": %m",
			  lstnr->listen_netif->name, lstnr->match->name,
			  inet_ntoa(lstnr->match->sa.sin.sin_addr),
			  ntohs(lstnr->match->sa.sin.sin_port));
	}

	err = setsockopt(lstnr->fd, SOL_SOCKET, SO_BINDTODEVICE,
			 lstnr->listen_netif->name,
			 strlen(lstnr->listen_netif->name) + 1);
	if (err) {
		FDF_FATAL("Failed to bind listener socket  (%1$s:%2$s) to "
					"interface (%1$s): %m",
			  lstnr->listen_netif->name, lstnr->match->name);
	}

	if (fdf_is_mcast(lstnr->match->sa.sin.sin_addr))
		fdf_listen_mcast(lstnr);
}

int fdf_init_listeners(void)
{
	struct epoll_event event;
	struct fdf_listener *l;
	int epfd;

	if ((epfd = epoll_create1(0)) < 0)
		FDF_PFATAL("epoll_create1");

	event.events = EPOLLIN;

	for (l = fdf_listeners; l != NULL; l = l->next) {

		fdf_listen_socket(l);

		event.data.ptr = l;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, l->fd, &event) != 0) {
			FDF_FATAL("EPOLL_CTL_ADD failed for listener socket "
						"(%s:%s): %m" ,
				  l->listen_netif->name, l->match->name);
		}
	}

	return epfd;
}

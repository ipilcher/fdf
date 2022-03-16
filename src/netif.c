// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	netif.c - Network interfaces
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>

static struct savl_node *fdf_netifs = NULL;

#define FDF_NETIF_FROM_NODE(_n)		\
	((_n) ? SAVL_NODE_CONTAINER((_n), struct fdf_netif, node) : NULL)

static int fdf_netif_cmp(const union savl_key key,
			 const struct savl_node *const node)
{
	return strcmp(FDF_NETIF_FROM_NODE(node)->name, key.p);
}

struct fdf_netif *fdf_get_netif(const char *const netif_name)
{
	union savl_key key;
	struct fdf_netif *netif;
	int sockfd;
	size_t name_len;
	struct ifreq ifr;
	const struct savl_node *existing;

	key.p = netif_name;
	netif = FDF_NETIF_FROM_NODE(savl_get(fdf_netifs, fdf_netif_cmp, key));

	if (netif != NULL)
		return netif;

	if ((name_len = strlen(netif_name)) >= IFNAMSIZ)
		FDF_FATAL("Interface name (%s) too long", netif_name);

	netif = FDF_ZALLOC(sizeof *netif);
	memcpy(netif->name, netif_name, name_len);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		FDF_PFATAL("socket");

	memset(&ifr, 0, sizeof ifr);
	memcpy(ifr.ifr_name, netif_name, name_len);

	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
		FDF_PFATAL(netif_name);

	netif->index = ifr.ifr_ifindex;

	if (close(sockfd) < 0)
		FDF_PFATAL("close");

	FDF_DEBUG("Found interface %s: index = %d", netif->name, netif->index);

	existing = savl_try_add(&fdf_netifs, fdf_netif_cmp, key, &netif->node);
	FDF_ASSERT(existing == NULL);

	return netif;
}

static void fdf_free_netif(struct savl_node *const node)
{
	free(FDF_NETIF_FROM_NODE(node));
}

void fdf_free_netifs(void)
{
	savl_free(&fdf_netifs, fdf_free_netif);
}

// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	process.c - Forward packets
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>

#define FDF_PROCESS_CONTINUE	1
#define FDF_PROCESS_DONE	0

#define FDF_IP4_HDR_ID		0xfdfd

_Static_assert(FDF_PKT_BUF_SIZE % 2 == 0, "FDF_PKT_BUF_SIZE not even");

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define HTONS(x)	(x)
#define HTONL(x)	(x)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HTONS(x)	((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8))
#define HTONL(x)	((((x) & 0x000000ff) << 24)		\
				| (((x) & 0x0000ff00) << 8)	\
				| (((x) & 0x00ff0000) >> 8)	\
				| (((x) & 0xff000000) >> 24))
#else
#error "__BYTE_ORDER__ is not __ORDER_BIG_ENDIAN__ or __ORDER_LITTLE_ENDIAN__"
#endif

struct fdf_ip4_hdr {			      /* fdf_udp4_pkt.ip4_words index */
/* Bit field order depends on byte order */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint8_t		version:4;			/* [0] */
	uint8_t		ihl:4;
	uint8_t		dscp:6;
	uint8_t		ecn:2;
#else
	uint8_t		ihl:4;
	uint8_t		version:4;
	uint8_t		ecn:2;
	uint8_t		dscp:6;
#endif
	uint16_t	length;				/* [1] */
	uint16_t	id;				/* [2] */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint8_t		frag_flag_reserved:1;		/* [3] */
	uint8_t		frag_flag_df:1;
	uint8_t		frag_flag_mf:1;
	uint8_t		frag_offset_hi_bits:5;
#else
	uint8_t		frag_offset_hi_bits:5;
	uint8_t		frag_flag_mf:1;
	uint8_t		frag_flag_df:1;
	uint8_t		frag_flag_reserved:1;
#endif
	uint8_t		frag_offset_lo_bits;
	uint8_t		ttl;				/* [4] */
	uint8_t		protocol;
	uint16_t	hdr_cksum;			/* [5] */
	struct in_addr	source_addr;			/* [6] - [7] */
	struct in_addr	dest_addr;			/* [8] - [9] */
};
_Static_assert(sizeof(struct fdf_ip4_hdr) == 20, "fdf_ip4_hdr size incorrect");

struct fdf_udp_hdr {
	uint16_t	source_port;
	uint16_t	dest_port;
	uint16_t	length;
	uint16_t	checksum;
};
_Static_assert(sizeof(struct fdf_udp_hdr) == 8, "fdf_udp_hdr size incorrect");

struct fdf_udp4_pkt {
	union {
		struct fdf_ip4_hdr	ip4;
		uint16_t		ip4_words[10];
	};
	struct fdf_udp_hdr		udp;
	union {
		uint8_t			data[FDF_PKT_BUF_SIZE];
		uint16_t		data_words[FDF_PKT_BUF_SIZE / 2];
	};
};
_Static_assert(sizeof(struct fdf_udp4_pkt) == 28 + FDF_PKT_BUF_SIZE,
	       "fdf_udp4_pkt size incorrect");

/* Ensure that data passed to filters is at least 4-byte aligned */
_Static_assert(__alignof__(struct fdf_udp4_pkt) >= 4,
	       "fdf_udp4_pkt alignment incorrect");
_Static_assert(offsetof(struct fdf_udp4_pkt, data) % 4 == 0,
	       "fdf_udp4_pkt.data offset incorrect");


static int fdf_send_fd;
static uint8_t fdf_cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
static struct sockaddr_in fdf_msg_dest = { .sin_family = AF_INET };
static struct iovec fdf_msg_iov;
static struct in_pktinfo fdf_msg_ipi;

static const struct msghdr fdf_msg = {
	.msg_name	= &fdf_msg_dest,
	.msg_namelen	= sizeof fdf_msg_dest,
	.msg_iov	= &fdf_msg_iov,
	.msg_iovlen	= 1,
	.msg_control	= fdf_cmsg_buf,
	.msg_controllen	= CMSG_LEN(sizeof fdf_msg_ipi)
};

void fdf_sender_init(void)
{
	struct cmsghdr *cmh;
	int err, sockopt;

	if ((fdf_send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		FDF_FATAL("Failed to create sender socket: %m");

	sockopt = 1;
	err = setsockopt(fdf_send_fd, SOL_SOCKET, SO_BROADCAST,
			 &sockopt, sizeof sockopt);
	if (err) {
		FDF_FATAL("Failed to set SO_BROADCAST option "
						"for sender socket: %m");
	}

	sockopt = 0;
	err = setsockopt(fdf_send_fd, IPPROTO_IP, IP_MULTICAST_LOOP,
			 &sockopt, sizeof sockopt);
	if (err) {
		FDF_FATAL("Failed to set IP_MULTICAST_LOOP option "
						"for sender socket: %m");
	}

	cmh = CMSG_FIRSTHDR(&fdf_msg);
	cmh->cmsg_len = CMSG_LEN(sizeof fdf_msg_ipi);
	cmh->cmsg_level = SOL_IP;
	cmh->cmsg_type = IP_PKTINFO;
}

void fdf_sender_close(void)
{
	if (close(fdf_send_fd) < 0)
		FDF_PFATAL("close");
}

static uint16_t fdf_ip4_hdr_cksum(const uint16_t *const hdr)
{
	uint32_t sum;
	unsigned int i;

	sum = 0;
	for (i = 0; i < 10; ++i) {
		if (i != 5)  /* skip checksum field */
			sum += ntohs(hdr[i]);
	}

	while ((sum & 0xffff0000) != 0)
		sum = (sum & 0x0000ffff) + (sum >> 16);

	return ~(uint16_t)sum;
}

static uint16_t fdf_udp4_cksum(struct fdf_udp4_pkt *const pkt, size_t data_size)
{
	uint32_t sum;
	unsigned int i;

	if (data_size % 2 != 0) {
		pkt->data[data_size] = 0;
		++data_size;
	}

	sum = 0;

	/*
	 *	IPv4 "pseudo header"
	 */

	/* Source and destination IP address */
	for (i = 6; i < 10; ++i)
		sum += ntohs(pkt->ip4_words[i]);

	/* Zero-padded protocol (IPPROTO_UDP) */
	sum += IPPROTO_UDP;

	/* "UDP length" */
	sum += ntohs(pkt->udp.length);

	/*
	 *	UDP header
	 */

	sum += ntohs(pkt->udp.source_port);
	sum += ntohs(pkt->udp.dest_port);
	sum += ntohs(pkt->udp.length);  /* Yes, again */

	/*
	 *	Payload
	 */

	for (i = 0; i < data_size / 2; ++i)
		sum += ntohs(pkt->data_words[i]);

	while ((sum & 0xffff0000) != 0)
		sum = (sum & 0x0000ffff) + (sum >> 16);

	/* If result would be 0, don't flip bits; 0 means no checksum */
	return sum == 0xffff ? 0xffff : ~(uint16_t)sum;
}

static void fdf_send_pkt(struct fdf_udp4_pkt *const pkt,
			 const size_t pkt_size,
			 const struct fdf_netif *const netif)
{
	ssize_t sent;

	fdf_msg_ipi.ipi_ifindex = netif->index;
	memcpy(CMSG_DATA(CMSG_FIRSTHDR(&fdf_msg)), &fdf_msg_ipi,
	       sizeof fdf_msg_ipi);

	fdf_msg_dest.sin_addr = pkt->ip4.dest_addr;
	fdf_msg_iov.iov_base = pkt;
	fdf_msg_iov.iov_len = pkt_size;

	if ((sent = sendmsg(fdf_send_fd, &fdf_msg, 0)) < 0) {
		FDF_FATAL("Error writing to sender socket (%s): %m",
			  netif->name);
	}

	if ((size_t)sent != pkt_size) {
		FDF_FATAL("Wrong number of bytes written to sender "
					"socket (%s): expected %zu, sent %zd",
			  netif->name, pkt_size, sent);
	}

	FDF_PKTLOG("  Sent packet via %s", netif->name);
}

static _Bool fdf_fwd_pkt(struct fdf_udp4_pkt *const pkt, const size_t data_size,
			 const struct sockaddr_in *const src,
			 const struct fdf_listener *const lstnr,
			 const struct fdf_netif *const fwd_netif)
{
	static const struct fdf_ip4_hdr template = {
		.version		= 4,
		.ihl			= 5,
		.dscp			= 0,
		.ecn			= 0,
		/* .length varies */
		.id			= HTONS(FDF_IP4_HDR_ID),
		.frag_flag_reserved	= 0,
		.frag_flag_df		= 1,
		.frag_flag_mf		= 0,
		.frag_offset_hi_bits	= 0,
		.frag_offset_lo_bits	= 0,
		.ttl			= 1,
		.protocol		= IPPROTO_UDP
		/* .hdr_cksum varies */
		/* .source_addr varies */
		/* .dest_addr varies */
	};

	unsigned int i;
	_Bool sent;

	memcpy(&pkt->ip4, &template, sizeof template);
	pkt->ip4.length = htons(28 + data_size);
	pkt->ip4.source_addr = src->sin_addr;
	pkt->ip4.dest_addr = lstnr->match->sa.sin.sin_addr;
	pkt->ip4.hdr_cksum = htons(fdf_ip4_hdr_cksum(pkt->ip4_words));

	pkt->udp.source_port = src->sin_port;
	pkt->udp.dest_port = lstnr->match->sa.sin.sin_port;
	pkt->udp.length = htons(sizeof pkt->udp + data_size);
	pkt->udp.checksum = htons(fdf_udp4_cksum(pkt, data_size));

	sent = 0;

	for (i = 0; i < lstnr->num_fwd_netifs; ++i) {

		if (fwd_netif != NULL && lstnr->fwd_netifs[i] != fwd_netif)
			continue;

		fdf_send_pkt(pkt, 28 + data_size, lstnr->fwd_netifs[i]);
		sent = 1;
	}

	return sent;
}

static _Bool fdf_process_pkt(const struct fdf_listener *const lstnr)
{
	static struct fdf_udp4_pkt pkt;

	union fdf_sockaddr src;
	socklen_t src_size;
	ssize_t data_size;
	_Bool passed;
	const struct fdf_netif *fwd_netif;

	src_size = sizeof src;
	data_size = recvfrom(lstnr->fd, pkt.data, sizeof pkt.data, MSG_TRUNC,
			     &src.sa, &src_size);
	if (data_size < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return FDF_PROCESS_DONE;
		FDF_FATAL("Error reading from listener socket (%s:%s): %m",
			  lstnr->listen_netif->name, lstnr->match->name);
	}

	FDF_ASSERT(src.sa.sa_family = AF_INET);

	if ((size_t)data_size > sizeof pkt.data) {
		FDF_WARNING("Ignoring oversize packet (%zd bytes) received from"
				" %s:%" PRIu16 " on listener socket (%s:%s)",
			    data_size, inet_ntoa(src.sin.sin_addr),
			    htons(src.sin.sin_port), lstnr->listen_netif->name,
			    lstnr->match->name);
		return FDF_PROCESS_CONTINUE;
	}

	FDF_PKTLOG("Received %zd bytes from %s:%" PRIu16 " on %s:%s", data_size,
		   inet_ntoa(src.sin.sin_addr), ntohs(src.sin.sin_port),
		   lstnr->listen_netif->name, lstnr->match->name);

	fwd_netif = NULL;

	if (lstnr->match->num_filters > 0) {

		passed = fdf_filter_match(lstnr, &src.ss,
					  pkt.data, data_size, &fwd_netif);
		if (!passed) {
			FDF_PKTLOG("  Packet did not pass filter(s); dropping");
			return FDF_PROCESS_CONTINUE;
		}

		FDF_PKTLOG("  Packet passed filter(s)");

		if (fwd_netif != NULL) {
			FDF_PKTLOG("  Filter(s) set output interface to %s",
				   fwd_netif->name);
		}
	}

	if (!fdf_fwd_pkt(&pkt, data_size, &src.sin, lstnr, fwd_netif)) {
		FDF_FATAL("A filter for listener %s:%s set packet output "
				"interface to %s, which is not a member of "
				"that listener's output interface list",
			  lstnr->listen_netif->name, lstnr->match->name,
			  fwd_netif->name);
	}

	return FDF_PROCESS_CONTINUE;
}

void fdf_process(const struct fdf_listener *const lstnr)
{
	while (fdf_process_pkt(lstnr) == FDF_PROCESS_CONTINUE);
}

// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	net-set.c - nftables set update "filter"
 *
 *	Copyright 2023 Ian Pilcher <arequipeno@gmail.com>
 */

#include <fdf-filter.h>

#include <ctype.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <string.h>
#include <syslog.h>

#define NFTSET_DEFAULT_TIMEOUT		30000	/* milliseconds */
#define NFTSET_DEFAULT_ADDR_FAMILY	NFPROTO_INET

struct nftset_instance {
	uint64_t	timeout;	/* milliseconds - network byte order */
	uint8_t		addr_family;	/* NFPROTO_INET or NFPROTO_IPV4 */
	const char	*table_name;
	const char	*set_name;
};

struct nftset_element {
	struct in_addr	address;
	uint16_t	port;		/* network byte order */
	uint16_t	_padding;	/* always zeroes? */
};

static struct mnl_socket *nftset_mnl_sock;
static uint32_t nftset_mnl_seq;
static unsigned int nftset_mnl_portid;
static uint8_t *nftset_buf;

static void nftset_mnl_cleanup(const uintptr_t handle)
{
	if (nftset_mnl_sock != NULL && mnl_socket_close(nftset_mnl_sock) != 0) {
		fdf_filter_log(handle, LOG_WARNING,
			       "Failed to close netlink socket: %m");
	}

	nftset_mnl_sock = NULL;

	if (nftset_buf != NULL) {
		free(nftset_buf);
		nftset_buf = NULL;
	}
}

static _Bool nftset_mnl_init(const uintptr_t handle)
{
	if ((nftset_buf = malloc(MNL_SOCKET_BUFFER_SIZE * 2)) == NULL) {
		fdf_filter_log(handle, LOG_CRIT, "Memory allocation failure");
		abort();
	}

	if ((nftset_mnl_sock = mnl_socket_open(NETLINK_NETFILTER)) == NULL) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to create netlink socket: %m");
		nftset_mnl_cleanup(handle);
		return 0;
	}

	if (mnl_socket_bind(nftset_mnl_sock, 0, MNL_SOCKET_AUTOPID) != 0) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to bind netlink socket: %m");
		nftset_mnl_cleanup(handle);
		return 0;
	}

	nftset_mnl_portid = mnl_socket_get_portid(nftset_mnl_sock);
	return 1;
}

static _Bool nftset_parse_table_name(const uintptr_t handle,
				     const char *const arg,
				     struct nftset_instance *const instance)
{
	if (instance->table_name != NULL) {
		fdf_filter_log(handle, LOG_ERR, "Table name already set");
		return 1;
	}

	instance->table_name = arg;
	fdf_filter_log(handle, LOG_DEBUG, "Instance table name: %s", arg);
	return 0;
}

static _Bool nftset_parse_set_name(const uintptr_t handle,
				   const char *const arg,
				   struct nftset_instance *const instance)
{
	if (instance->set_name != NULL) {
		fdf_filter_log(handle, LOG_ERR, "Set name already set");
		return 1;
	}

	instance->set_name = arg;
	fdf_filter_log(handle, LOG_DEBUG, "Instance set name: %s", arg);
	return 0;
}

static _Bool nftset_parse_af(const uintptr_t handle, const char *const arg,
			     struct nftset_instance *const instance)
{
	if (instance->addr_family != NFPROTO_UNSPEC) {
		fdf_filter_log(handle, LOG_ERR, "Address family already set");
		return 1;
	}

	if (strcasecmp(arg, "inet") == 0) {
		instance->addr_family = NFPROTO_INET;
		fdf_filter_log(handle, LOG_DEBUG,
			       "Instance address family: inet");
		return 0;
	}

	if (strcasecmp(arg, "ip") == 0) {
		instance->addr_family = NFPROTO_IPV4;
		fdf_filter_log(handle, LOG_DEBUG,
			       "Instance address family: ip");
		return 0;
	}

	fdf_filter_log(handle, LOG_ERR, "Unknown address family: %s", arg);
	return 1;
}

static _Bool nftset_parse_timeout(const uintptr_t handle, const char *const arg,
				  struct nftset_instance *const instance)
{
	char *endptr;
	unsigned long timeout;

	if (instance->timeout != UINT64_MAX) {
		fdf_filter_log(handle, LOG_ERR, "Timeout already set");
		return 1;
	}

	if (!isdigit(*arg)) {
		fdf_filter_log(handle, LOG_ERR, "Invalid timeout: %s", arg);
		return 1;
	}

	errno = 0;
	timeout = strtoul(arg, &endptr, 10);
	if (errno != 0 || timeout > 32000000) {  /* a bit more than 1 year */
		fdf_filter_log(handle, LOG_ERR, "Invalid timeout: %s", arg);
		return 1;
	}

	instance->timeout = htobe64(timeout * 1000);
	fdf_filter_log(handle, LOG_DEBUG, "Instance timeout: %s", arg);
	return 0;
}

static _Bool nftset_init(const uintptr_t handle, const int argc,
			 const char *const *const argv)
{
	struct nftset_instance *instance;
	int i;
	_Bool err;

	if (argc < 4 || argc > 6) {
		fdf_filter_log(handle, LOG_ERR,
			       "%s requires between 2 and 4 arguments",
			       argv[1]);
		return 0;
	}

	if ((instance = malloc(sizeof *instance)) == NULL) {
		fdf_filter_log(handle, LOG_CRIT, "Memory allocation failure");
		abort();
	}

	instance->timeout = UINT64_MAX;

	for (i = 2; i < argc; ++i) {

		if (strncmp(argv[i], "table_name=", 11) == 0) {
			err = nftset_parse_table_name(handle, argv[i] + 11,
						      instance);
		}
		else if (strncmp(argv[i], "set_name=", 9) == 0) {
			err = nftset_parse_set_name(handle, argv[i] + 9,
						    instance);
		}
		else if (strncmp(argv[i], "timeout=", 8) == 0) {
			err = nftset_parse_timeout(handle, argv[i] + 8,
						   instance);
		}
		else if (strncmp(argv[i], "address_family=", 15) == 0) {
			err = nftset_parse_af(handle, argv[i] + 15, instance);
		}
		else {
			fdf_filter_log(handle, LOG_ERR, "Unknown argument: %s",
				       argv[i]);
			err = 1;
		}

		if (err)
			return 0;
	}

	if (instance->table_name == NULL) {
		fdf_filter_log(handle, LOG_ERR, "Missing argument: table_name");
		return 0;
	}

	if (instance->set_name == NULL) {
		fdf_filter_log(handle, LOG_ERR, "Missing argument: set_name");
		return 0;
	}

	if (instance->timeout == UINT64_MAX)
		instance->timeout = htobe64(NFTSET_DEFAULT_TIMEOUT);
	if (instance->addr_family == NFPROTO_UNSPEC)
		instance->addr_family = NFTSET_DEFAULT_ADDR_FAMILY;

	if (nftset_mnl_sock == NULL && !nftset_mnl_init(handle)) {
		free(instance);
		return 0;
	}

	fdf_filter_set_data(handle, (union fdf_filter_data){ .p = instance });

	return 1;
}

static void nftset_cleanup(const uintptr_t handle)
{
	free(fdf_filter_get_data(handle).p);
	nftset_mnl_cleanup(handle);
}

static void nftset_batch_msg(struct mnl_nlmsg_batch *const batch,
			     const uint16_t msg_type)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_seq = nftset_mnl_seq++;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof *nfg);
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version=NFNETLINK_V0;
	nfg->res_id = htobe16(NFNL_SUBSYS_NFTABLES);
}

static _Bool nftset_batch_next(const uintptr_t handle,
			       struct mnl_nlmsg_batch *const batch)
{
	if (!mnl_nlmsg_batch_next(batch)) {
		fdf_filter_log(handle, LOG_ERR, "Message batch too large");
		return 1;
	}

	return 0;
}

static void nftset_elem_msg(struct mnl_nlmsg_batch *const batch,
			    const uint16_t msg_type,
			    const struct nftset_element *const element,
			    const struct nftset_instance *const instance,
			    const _Bool add_timeout)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	struct nlattr *elem_list_attr, *elem_attr, *key_attr;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | msg_type;
	nlh->nlmsg_seq = nftset_mnl_seq++;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (msg_type == NFT_MSG_NEWSETELEM)
		nlh->nlmsg_flags |= NLM_F_CREATE;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof *nfg);
	nfg->nfgen_family = NFPROTO_INET;
	nfg->version=NFNETLINK_V0;
	nfg->res_id = 0;

	mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, instance->table_name);
	mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, instance->set_name);

	elem_list_attr = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
	elem_attr = mnl_attr_nest_start(nlh, 1);  /* nla_type is index # */
	if (add_timeout != 0)
		mnl_attr_put_u64(nlh, NFTA_SET_ELEM_TIMEOUT, instance->timeout);

	key_attr = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_KEY);
	mnl_attr_put(nlh, NFTA_DATA_VALUE, sizeof *element, element);

	mnl_attr_nest_end(nlh, key_attr);
	mnl_attr_nest_end(nlh, elem_attr);
	mnl_attr_nest_end(nlh, elem_list_attr);
}

static size_t nftset_build_batch(const uintptr_t handle,
				 const struct sockaddr_in *const sockaddr,
				 const struct nftset_instance *const instance)
{
	struct nftset_element element;
	struct mnl_nlmsg_batch *batch;
	size_t len;

	element.address.s_addr = sockaddr->sin_addr.s_addr;
	element.port = sockaddr->sin_port;
	element._padding = 0;

	batch = mnl_nlmsg_batch_start(nftset_buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to initialize message batch");
		return 0;
	}

	nftset_batch_msg(batch, NFNL_MSG_BATCH_BEGIN);
	if (nftset_batch_next(handle, batch))
		return 0;

	nftset_elem_msg(batch, NFT_MSG_NEWSETELEM, &element, instance, 0);
	if (nftset_batch_next(handle, batch))
		return 0;

	nftset_elem_msg(batch, NFT_MSG_DELSETELEM, &element, instance, 0);
	if (nftset_batch_next(handle, batch))
		return 0;

	nftset_elem_msg(batch, NFT_MSG_NEWSETELEM, &element, instance, 1);
	if (nftset_batch_next(handle, batch))
		return 0;

	nftset_batch_msg(batch, NFNL_MSG_BATCH_END);
	if (nftset_batch_next(handle, batch))  /* Check last message fits */
		return 0;

	len = mnl_nlmsg_batch_size(batch);
	mnl_nlmsg_batch_stop(batch);
	return len;
}



static uint8_t nftset_match(const uintptr_t handle,
			const struct sockaddr_storage *restrict const src_ss,
			const struct sockaddr_storage *restrict const dest
				__attribute__((unused)),
			const void *restrict const pkt __attribute((unused)),
			const size_t pkt_size __attribute__((unused)),
			const uintptr_t in_netif __attribute__((unused)),
			uintptr_t *const fwd_netif_out __attribute__((unused)))
{
	const struct nftset_instance *instance;
	size_t len;
	unsigned int i;
	ssize_t got;
	int rc;
	char src_buf[FDF_FILTER_SA4_LEN];

	if (src_ss->ss_family != AF_INET) {
		fdf_filter_log(handle, LOG_WARNING,
			       "Unsupported address family: %u",
			       src_ss->ss_family);
		return FDF_FILTER_DROP_NOW;
	}

	instance = fdf_filter_get_data(handle).p;
	len = nftset_build_batch(handle, (const struct sockaddr_in *)src_ss,
				 instance);
	if (len == 0)
		return FDF_FILTER_DROP_NOW;

	if (mnl_socket_sendto(nftset_mnl_sock, nftset_buf, len) < 0) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to send netlink message: %m");
		return FDF_FILTER_DROP_NOW;
	}

	for (i = 0; i < 3; ++i) {  /* Should receive 3 separate ACKs */

		got = mnl_socket_recvfrom(nftset_mnl_sock, nftset_buf,
					  MNL_SOCKET_BUFFER_SIZE);
		if (got < 0) {
			fdf_filter_log(handle, LOG_ERR,
				       "Failed to receive netlink message: %m");
			return FDF_FILTER_DROP_NOW;
		}

		rc = mnl_cb_run(nftset_buf, got, 0, nftset_mnl_portid,
				NULL, NULL);
		if (rc < 0) {
			fdf_filter_log(handle, LOG_ERR, "Netlink error: %m");
			return FDF_FILTER_DROP_NOW;
		}
	}

	fdf_filter_sock_addr(handle, src_ss, src_buf, sizeof src_buf);
	fdf_filter_log(handle, LOG_DEBUG, "Added %s to %s:%s", src_buf,
		       instance->table_name, instance->set_name);
	return FDF_FILTER_PASS;
}

FDF_FILTER(nftset_init, nftset_match, nftset_cleanup);

// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	ipset.c - IP set update "filter"
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include <fdf-filter.h>

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define IPSET_FDF_DEFAULT_TIMEOUT	30
#define IPSET_FDF_DEFAULT_IPPROTO	IPPROTO_UDP

struct ipset_instance {
	uint32_t	timeout;
	uint8_t		ip_proto;
	char		set_name[];
};

static struct mnl_socket *ipset_mnl = NULL;
static uint8_t *ipset_msgbuf = NULL;
static uint8_t ipset_proto_ver;
static size_t  ipset_buf_size;
static uint32_t ipset_mnl_seq;
static unsigned int ipset_mnl_portid;

static struct nlmsghdr *ipset_init_msg(void)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(ipset_msgbuf);
	nlh->nlmsg_type = NFNL_SUBSYS_IPSET << 8;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = ++ipset_mnl_seq;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof *nfg);
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, ipset_proto_ver);

	return nlh;
}

static int ipset_do_msg(const uintptr_t handle,
			const struct nlmsghdr *const nlh, const mnl_cb_t msg_cb)
{
	ssize_t bytes;
	int ret;

	if (mnl_socket_sendto(ipset_mnl, nlh, nlh->nlmsg_len) < 0) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to send message to netlink socket: %m");
		return MNL_CB_ERROR;
	}

	bytes = mnl_socket_recvfrom(ipset_mnl, ipset_msgbuf, ipset_buf_size);
	if (bytes < 0) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to receive message from netlink socket:"
			       " %m");
		return MNL_CB_ERROR;
	}

	ret = mnl_cb_run(ipset_msgbuf, bytes, ipset_mnl_seq,
			 ipset_mnl_portid, msg_cb, NULL);
	if (ret < 0) {
		fdf_filter_log(handle, LOG_ERR, "IP set netlink error: %m");
		return MNL_CB_ERROR;
	}

	return ret;
}

static _Bool ipset_parse_set_name(const uintptr_t handle, const char *const arg,
				 const char **const set_name)
{
	if (*set_name != NULL) {
		fdf_filter_log(handle, LOG_ERR, "IP set name already set");
		return 1;
	}

	*set_name = arg;

	fdf_filter_log(handle, LOG_DEBUG, "Instance IP set name: %s", arg);

	return 0;
}

static _Bool ipset_parse_ipproto(const uintptr_t handle, const char *const arg,
				uint8_t *const ip_proto)
{
	if (*ip_proto != 0) {
		fdf_filter_log(handle, LOG_ERR, "IP protocol already set");
		return 1;
	}

	if (strcasecmp(arg, "udp") == 0) {
		*ip_proto = IPPROTO_UDP;
		fdf_filter_log(handle, LOG_DEBUG, "Instance IP protocol: UDP");
		return 0;
	}

	if (strcasecmp(arg, "tcp") == 0) {
		*ip_proto = IPPROTO_TCP;
		fdf_filter_log(handle, LOG_DEBUG, "Instance IP protocol: TCP");
		return 0;
	}
	else {
		fdf_filter_log(handle, LOG_ERR, "Unknown IP protocol: %s", arg);
		return 1;
	}
}

static _Bool ipset_parse_timeout(const uintptr_t handle, const char *const arg,
				 uint32_t *const timeout)
{
	char *endptr;

	if (*timeout != UINT32_MAX) {
		fdf_filter_log(handle, LOG_ERR, "Timeout already set");
		return 1;
	}

	if (!isdigit(*arg)) {
		fdf_filter_log(handle, LOG_ERR, "Invalid timeout: %s", arg);
		return 1;
	}

	errno = 0;
	*timeout = strtoul(arg, &endptr, 0);
	if (errno != 0 || *timeout > 2147483) {  /* max IP set timeout */
		fdf_filter_log(handle, LOG_ERR, "Invalid timeout: %s", arg);
		return 1;
	}

	fdf_filter_log(handle, LOG_DEBUG,
		       "Instance IP set entry timeout: %" PRIu32 " seconds",
		       *timeout);

	return 0;
}

static void ipset_mnl_cleanup(const uintptr_t handle)
{
	if (ipset_mnl != NULL && mnl_socket_close(ipset_mnl) != 0) {
		fdf_filter_log(handle, LOG_WARNING,
			       "Failed to close netlink socket: %m");
	}

	ipset_mnl = NULL;

	free(ipset_msgbuf);
	ipset_msgbuf = NULL;
}

static int ipset_proto_attr_cb(const struct nlattr *const attr,
			       void *const data __attribute__((unused)))
{
	if (attr->nla_type == IPSET_ATTR_PROTOCOL) {
		ipset_proto_ver = mnl_attr_get_u8(attr);
		return MNL_CB_STOP;
	}

	return MNL_CB_OK;
}

static int ipset_proto_msg_cb(const struct nlmsghdr *const nlh,
			      void *const data __attribute__((unused)))
{
	return mnl_attr_parse(nlh, NLMSG_ALIGN(sizeof(struct nfgenmsg)),
			      ipset_proto_attr_cb, NULL);
}

static _Bool ipset_init_mnl(const uintptr_t handle)
{
	struct nlmsghdr *nlh;

	ipset_buf_size = MNL_SOCKET_BUFFER_SIZE;

	if ((ipset_msgbuf = malloc(ipset_buf_size)) == NULL) {
		fdf_filter_log(handle, LOG_CRIT, "Memory allocation failure");
		abort();
	}

	if ((ipset_mnl = mnl_socket_open(NETLINK_NETFILTER)) == NULL) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to create netlink socket: %m");
		ipset_mnl_cleanup(handle);
		return 0;
	}

	if (mnl_socket_bind(ipset_mnl, 0, MNL_SOCKET_AUTOPID) != 0) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to bind netlink socket: %m");
		ipset_mnl_cleanup(handle);
		return 0;
	}

	ipset_mnl_portid = mnl_socket_get_portid(ipset_mnl);
	ipset_mnl_seq = time(NULL);
	ipset_proto_ver = UINT8_MAX;

	nlh = ipset_init_msg();
	nlh->nlmsg_type |= IPSET_CMD_PROTOCOL;

	if (ipset_do_msg(handle, nlh, ipset_proto_msg_cb) < 0) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to get IP set protocol version");
		ipset_mnl_cleanup(handle);
		return 0;
	}

	if (ipset_proto_ver == UINT8_MAX) {
		fdf_filter_log(handle, LOG_ERR,
			       "Kernel did not return IP set protocol version");
		ipset_mnl_cleanup(handle);
		return 0;
	}

	return 1;
}

static _Bool ipset_init(const uintptr_t handle,
			const int argc, const char *const *const argv)
{
	struct ipset_instance *inst_data;
	const char *set_name;
	size_t name_size;
	uint32_t timeout;
	uint8_t ip_proto;
	_Bool err;
	int i;

	if (argc < 3 || argc > 5) {
		fdf_filter_log(handle, LOG_ERR,
			       "%s requires between 1 and 3 arguments",
			       argv[1]);
		return 0;
	}

	set_name = NULL;
	timeout = UINT32_MAX;
	ip_proto = 0;

	for (i = 2; i < argc; ++i) {

		if (strncmp(argv[i], "set_name=", 9) == 0) {
			err = ipset_parse_set_name(handle, argv[i] + 9,
						   &set_name);
		}
		else if (strncmp(argv[i], "protocol=", 9) == 0) {
			err = ipset_parse_ipproto(handle, argv[i] + 9,
						  &ip_proto);
		}
		else if (strncmp(argv[i], "timeout=", 8) == 0) {
			err = ipset_parse_timeout(handle, argv[i] + 8,
						  &timeout);
		}
		else {
			fdf_filter_log(handle, LOG_ERR,
				       "Unknown argument: %s", argv[i]);
			err = 1;
		}

		if (err)
			return 0;
	}

	if (set_name == NULL) {
		fdf_filter_log(handle, LOG_ERR, "set_name argument required");
		return 0;
	}

	if (timeout == UINT32_MAX)
		timeout = IPSET_FDF_DEFAULT_TIMEOUT;
	if (ip_proto == 0)
		ip_proto = IPSET_FDF_DEFAULT_IPPROTO;

	name_size = strlen(set_name) + 1;

	if ((inst_data = malloc(sizeof *inst_data + name_size)) == NULL) {
		fdf_filter_log(handle, LOG_CRIT, "Memory allocation failure");
		abort();
	}

	inst_data->timeout = timeout;
	inst_data->ip_proto = ip_proto;
	memcpy(inst_data->set_name, set_name, name_size);

	if (ipset_mnl == NULL && !ipset_init_mnl(handle)) {
		free(inst_data);
		return 0;
	}

	fdf_filter_set_data(handle, (union fdf_filter_data){ .p = inst_data });

	return 1;
}

static void ipset_cleanup(const uintptr_t handle)
{
	free(fdf_filter_get_data(handle).p);
	ipset_mnl_cleanup(handle);
}

static uint8_t ipset_match(const uintptr_t handle,
			   const struct sockaddr_storage *restrict const src_ss,
			   const struct sockaddr_storage *restrict const dest
							__attribute__((unused)),
			   const void *restrict const pkt __attribute((unused)),
			   const size_t pkt_size __attribute__((unused)),
			   const uintptr_t in_netif __attribute__((unused)),
			   uintptr_t *const fwd_netif_out
						__attribute__((unused)))
{
	struct nlattr *entry_attr, *addr_attr;
	struct ipset_instance *inst_data;
	const struct sockaddr_in *src;
	char src_buf[FDF_FILTER_SA4_LEN];
	struct nlmsghdr *nlh;

	if (src_ss->ss_family != AF_INET) {
		fdf_filter_log(handle, LOG_WARNING,
			       "Unsupported address family: %u",
			       src_ss->ss_family);
		return FDF_FILTER_DROP_NOW;
	}

	src = (const struct sockaddr_in *)src_ss;

	inst_data = fdf_filter_get_data(handle).p;

	nlh = ipset_init_msg();
	nlh->nlmsg_type |= IPSET_CMD_ADD;
	nlh->nlmsg_flags |= (NLM_F_ACK | NLM_F_CREATE);

	mnl_attr_put_strz(nlh, IPSET_ATTR_SETNAME, inst_data->set_name);
	entry_attr = mnl_attr_nest_start(nlh, IPSET_ATTR_DATA);
	addr_attr = mnl_attr_nest_start(nlh, IPSET_ATTR_IP);
	mnl_attr_put_u32(nlh, IPSET_ATTR_IP | NLA_F_NET_BYTEORDER,
			 src->sin_addr.s_addr);
	mnl_attr_nest_end(nlh, addr_attr);
	mnl_attr_put_u16(nlh, IPSET_ATTR_PORT | NLA_F_NET_BYTEORDER,
			 src->sin_port);
	mnl_attr_put_u32(nlh, IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER,
			 htonl(inst_data->timeout));
	mnl_attr_put_u8(nlh, IPSET_ATTR_PROTO, inst_data->ip_proto);
	mnl_attr_nest_end(nlh, entry_attr);

	fdf_filter_sock_addr(handle, src_ss, src_buf, sizeof src_buf);

	if (ipset_do_msg(handle, nlh, NULL) < 0) {
		fdf_filter_log(handle, LOG_ERR,
			       "Failed to add source (%s) to IP set (%s)",
			       src_buf, inst_data->set_name);
		return FDF_FILTER_DROP_NOW;
	}

	fdf_filter_log(handle, LOG_DEBUG, "Added source (%s) to IP set (%s)",
		       src_buf, inst_data->set_name);

	return FDF_FILTER_PASS;
}

FDF_FILTER(ipset_init, ipset_match, ipset_cleanup);

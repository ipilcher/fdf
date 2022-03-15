// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	mdns.c - Stateful multicast DNS filter
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include <fdf-filter.h>

#include <errno.h>
#include <inttypes.h>
#include <savl.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>

#define MDNS_FLAG_FWD_RESP	1
#define MDNS_FLAG_CHAINED	2

#define MDNS_FLAG_FWD_SET	(MDNS_FLAG_FWD_RESP << 16)
#define MDNS_FLAG_CHAINED_SET	(MDNS_FLAG_CHAINED << 16)

#define MDNS_MODE_STATELESS	0
#define MDNS_MODE_STATEFUL	1

#define MDNS_DNS_HDR_SIZE	12
#define MDNS_CLASS_COUNT	4
#define MDNS_CLASS_IN		1
#define MDNS_TYPE_ANY		255

#define MDNS_QCLASS_QU		0x8000  /* High bit of qclass is QU */
#define MDNS_CLASS_CF		0x8000  /* High bit of class is cache flush */

union mdns_pkt {
	struct {
		uint8_t				raw[1];
	};
	struct {
		uint16_t			id;
		union {
			uint16_t		flags;
			struct {
	/* Bitfield order depends on endianness */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
				uint8_t		qr:1;
				uint8_t		opcode:4;
				uint8_t		aa:1;
				uint8_t		tc:1;
				uint8_t		rd:1;
				uint8_t		ra:1;
				uint8_t		z:1;
				uint8_t		ad:1;
				uint8_t		cd:1;
				uint8_t		rcode:4;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
				uint8_t		rd:1;
				uint8_t		tc:1;
				uint8_t		aa:1;
				uint8_t		opcode:4;
				uint8_t		qr:1;
				uint8_t		rcode:4;
				uint8_t		cd:1;
				uint8_t		ad:1;
				uint8_t		z:1;
				uint8_t		ra:1;
			};
		};
#else
#error "__BYTE_ORDER__ is not __ORDER_BIG_ENDIAN__ or __ORDER_LITTLE_ENDIAN__"
#endif
		uint16_t			qdcount;
		uint16_t			ancount;
		uint16_t			nscount;
		uint16_t			arcount;
	};
};
_Static_assert(sizeof(union mdns_pkt) == MDNS_DNS_HDR_SIZE,
	       "mdns_dns_hdr size incorrect");

struct mdns_common {
	union {
		char		*qname;
		char		*name;
	};
	unsigned int		size;
	union {
		uint16_t	qtype;
		uint16_t	type;
	};
	union {
		uint16_t	qclass;  /* high bit is QU bit */
		uint16_t	class;   /* high bit is cache-flush bit */
	};
};

struct mdns_question {
	struct mdns_common	c;
	time_t			expires;
	uintptr_t		netif;
	struct savl_node	node;
	struct mdns_question	*older;
	struct mdns_question	*newer;
};

struct mdns_rr {
	struct mdns_common	c;
	uint32_t		ttl;
	uint16_t		rdlength;
};

struct mdns_type {
	uint16_t	type;
	const char *	name;
};

static _Bool mdns_mode = MDNS_MODE_STATELESS;
static _Bool mdns_mode_set = 0;

static uint16_t mdns_query_life = 30;
static _Bool mdns_qlife_set = 0;

static struct savl_node *mdns_questions = NULL;
static struct mdns_question *mdns_oldest = NULL;
static struct mdns_question *mdns_newest = NULL;

#define MDNS_QUESTION_FROM_NODE(_n)	\
	((_n) ? SAVL_NODE_CONTAINER((_n), struct mdns_question, node) : NULL)

static void mdns_free_question(struct mdns_question *const q)
{
	free(q->c.qname);
	free(q);
}

static void mdns_free_rr(struct mdns_rr *const rr)
{
	free(rr->c.name);
	free(rr);
}

static int mdns_question_cmp(const union savl_key key,
			     const struct savl_node *const node)
{
	const struct mdns_common *k;  /* may be question or answer */
	const struct mdns_question *n;
	int result;

	k = key.p;
	n = MDNS_QUESTION_FROM_NODE(node);

	if ((result = strcmp(k->name, n->c.qname)) != 0)
		return result;

	/* Ignore class; should always be IN */

	return (int)k->type - (int)n->c.qtype;
}

static void mdns_add_question(struct mdns_question *question,
			      const uintptr_t netif, const time_t now)
{
	struct savl_node *existing_node;
	struct mdns_question *existing;

	question->netif = netif;
	question->expires = now + mdns_query_life;

	existing_node = savl_force_add(&mdns_questions, mdns_question_cmp,
				       (union savl_key){ .p = &question->c },
				       &question->node);

	if (existing_node != NULL) {

		existing = MDNS_QUESTION_FROM_NODE(existing_node);

		if (existing->older != NULL)
			existing->older->newer = existing->newer;
		else
			mdns_oldest = existing->newer;

		if (existing->newer != NULL)
			existing->newer->older = existing->older;
		else
			mdns_newest = existing->older;

		mdns_free_question(existing);
	}

	question->older = mdns_newest;
	question->newer = NULL;
	mdns_newest = question;

	if (mdns_oldest == NULL)
		mdns_oldest = question;
}

static void mdns_remove_old(const uintptr_t handle, const time_t now)
{
	struct mdns_question *q, *newer;

	q = mdns_oldest;

	while (q != NULL && q->expires < now) {
		fdf_filter_log(handle, LOG_DEBUG,
			       "Removing question: %s (expired %ld seconds ago)",
			       q->c.qname, now - q->expires);
		savl_remove_node(&q->node, &mdns_questions);
		newer = q->newer;
		mdns_free_question(q);
		q = newer;
	}

	mdns_oldest = q;

	if (q != NULL)
		q->older = NULL;
	else
		mdns_newest = NULL;
}

static void mdns_free_questions(void)
{
	struct mdns_question *q, *newer;

	q = mdns_oldest;

	while (q != NULL) {
		newer = q->newer;
		mdns_free_question(q);
		q = newer;
	}

	mdns_oldest = NULL;
	mdns_newest = NULL;
	mdns_questions = NULL;
}

static int mdns_type_cmp(const void *const a, const void *const b)
{
	return (int)(intptr_t)a - (int)((const struct mdns_type *)b)->type;
}

static const char *mdns_type_name(uint16_t t)
{
	/* https://en.wikipedia.org/wiki/List_of_DNS_record_types */
	static const struct mdns_type types[] = {
		{     1, "A"		},	{     2, "NS"		},
		{     3, "MD"		},	{     4, "MF"		},
		{     5, "CNAME"	},	{     6, "SOA"		},
		{     7, "MB"		},	{     8, "MG"		},
		{     9, "MR"		},	{    10, "NULL"		},
		{    11, "WKS"		},	{    12, "PTR"		},
		{    13, "HINFO"	},	{    14, "MINFO"	},
		{    15, "MX"		},	{    16, "TXT"		},
		{    17, "RP"		},	{    18, "AFSDB"	},
		{    19, "X25"		},	{    20, "ISDN"		},
		{    21, "RT"		},	{    22, "NSAP"		},
		{    23, "NSAP-PTR"	},	{    24, "SIG"		},
		{    25, "KEY"		},	{    26, "PX"		},
		{    27, "GPOS"		},	{    28, "AAAA"		},
		{    29, "LOC"		},	{    30, "NXT"		},
		{    31, "EID"		},	{    32, "NIMLOC"	},
		{    33, "SRV"		},	{    34, "ATMA"		},
		{    35, "NAPTR"	},	{    36, "KX"		},
		{    37, "CERT"		},	{    38, "A6"		},
		{    39, "DNAME"	},	{    40, "SINK"		},
		{    41, "OPT"		},	{    42, "APL"		},
		{    43, "DS"		},	{    44, "SSHFP"	},
		{    45, "IPSECKEY"	},	{    46, "RRSIG"	},
		{    47, "NSEC"		},	{    48, "DNSKEY"	},
		{    49, "DHCID"	},	{    50, "NSEC3"	},
		{    51, "NSEC3PARAM"	},	{    52, "TLSA"		},
		{    53, "SMIMEA"	},	{    55, "HIP"		},
		{    56, "NINFO"	},	{    57, "RKEY"		},
		{    58, "TALINK"	},	{    59, "CDS"		},
		{    60, "CDNSKEY"	},	{    61, "OPENPGPKEY"	},
		{    62, "CSYNC"	},	{    63, "ZONEMD"	},
		{    64, "SVCB"		},	{    65, "HTTPS"	},
		{    99, "SPF"		},	{   100, "UINFO"	},
		{   101, "UID"		},	{   102, "GID"		},
		{   103, "UNSPEC"	},	{   104, "NID"		},
		{   105, "L32"		},	{   106, "L64"		},
		{   107, "LP"		},	{   108, "EUI48"	},
		{   109, "EUI64"	},	{   249, "TKEY"		},
		{   250, "TSIG"		},	{   251, "IXFR"		},
		{   252, "AXFR"		},	{   253, "MAILB"	},
		{   254, "MAIL"		},	{   255, "*"		},
		{   256, "URI"		},	{   257, "CAA"		},
		{   259, "DOA"		},	{ 32768, "TA"		},
		{ 32769, "DLV"		}
	};

	static char buf[sizeof "(65535)"];

	const struct mdns_type *type;

	t &= ~ MDNS_QCLASS_QU;  /* ignore QU bit */

	type = bsearch((void *)(intptr_t)t, types,
		       sizeof types / sizeof types[0],
		       sizeof types[0], mdns_type_cmp);
	if (type != NULL)
		return type->name;

	sprintf(buf, "(%" PRIu16 ")", t);
	return buf;
}

static const char *mdns_class_name(uint16_t class)
{
	static const char *const class_names[MDNS_CLASS_COUNT]
					= { "IN", "CS", "CH", "HS" };

	static char buf[sizeof "(65535)"];

	class &= ~MDNS_CLASS_CF;  /* ignore cache flush bit */

	if (class >= 1 && class <= MDNS_CLASS_COUNT)
		return class_names[class - 1];

	if (class == 255)
		return "ANY";

	sprintf(buf, "(%" PRIu16 ")", class);
	return buf;
}

static _Bool mdns_is_query(const union mdns_pkt *const dns)
{
	return dns->qr == 0 && dns->opcode == 0 && dns->qdcount > 0;
}

static _Bool mdns_is_answer(const union mdns_pkt *const dns)
{
	return dns->qr == 1 && dns->opcode == 0 && dns->ancount > 0;
}

static uint16_t mdns_get_unaligned_u16(const uint8_t *const ptr)
{
	struct unaligned_u16 { uint16_t value; } __attribute__((packed));

	const struct unaligned_u16 *uptr;

	uptr = (const struct unaligned_u16 *)ptr;
	return ntohs(uptr->value);
}

static uint32_t mdns_get_unaligned_u32(const uint8_t *const ptr)
{
	struct unaligned_u32 { uint32_t value; } __attribute__((packed));

	const struct unaligned_u32 *uptr;

	uptr = (const struct unaligned_u32 *)ptr;
	return ntohl(uptr->value);
}

static _Bool mdns_check_size(const uintptr_t handle, const unsigned int size,
			     const ptrdiff_t remaining)
{
	if (remaining < 0 || (size_t)remaining < size) {
		fdf_filter_log(handle, LOG_ERR, "Malformed packet");
		return 0;
	}

	return 1;
}

static char *mdns_strdup(const uintptr_t handle, const char *const s)
{
	char *copy;

	if ((copy = strdup(s)) == NULL)
		fdf_filter_log(handle, LOG_CRIT, "Memory allocation error");

	return copy;
}

static unsigned int mdns_parse_name(const uintptr_t handle,
				    const uint8_t  *labels,
				    const union mdns_pkt *pkt,
				    const size_t pkt_size,
				    char **const name_out)
{
	static char buf[256];

	unsigned int name_size, labels_size;
	uint8_t label_len;
	uint16_t offset;
	_Bool haz_ptr;
	const uint8_t *pkt_end;
	ptrdiff_t remaining;

	pkt_end = pkt->raw + pkt_size;  /* points to octet *after* packet */
	name_size = 0;
	labels_size = 0;
	haz_ptr = 0;

	while (1) {
		remaining = pkt_end - labels;

		if (!mdns_check_size(handle, 1, remaining))
			return 0;

		if ((label_len = *labels) == 0)
			break;

		if (label_len & 0xc0) {  /* message compression pointer? */

			if (!mdns_check_size(handle, 2, remaining))
				return 0;

			labels_size += 2 * !haz_ptr;
			haz_ptr = 1;
			offset = mdns_get_unaligned_u16(labels) & 0x3fff;
			labels = pkt->raw + offset;
			continue;
		}

		if (!mdns_check_size(handle, label_len + 1, remaining))
			return 0;

		if (name_size + label_len + 1 >= sizeof buf) {
			fdf_filter_log(handle, LOG_ERR, "Name too long");
			return 0;
		}

		memcpy(buf + name_size, labels + 1, label_len);
		buf[name_size + label_len] = '.';
		name_size += label_len + 1;
		labels_size += (label_len + 1) * !haz_ptr;
		labels += label_len + 1;
	}

	labels_size += !haz_ptr;
	buf[name_size] = 0;
	++name_size;

	if ((*name_out = mdns_strdup(handle, buf)) == NULL)
		return 0;

	return labels_size;
}

static struct mdns_question *mdns_parse_question(const uintptr_t handle,
						 const union mdns_pkt *pkt,
						 const size_t pkt_size,
						 unsigned int offset)
{
	struct mdns_question *question;
	const uint8_t *sect;
	unsigned int qname_size;
	char *qname;

	if (pkt_size < offset + 5) {  /* root + type & class */
		fdf_filter_log(handle, LOG_CRIT, "Packet too small for answer");
		return NULL;
	}

	sect = pkt->raw + offset;

	qname_size = mdns_parse_name(handle, sect, pkt, pkt_size, &qname);
	if (qname_size == 0)
		return NULL;

	if (pkt_size < offset + qname_size + 4) {
		fdf_filter_log(handle, LOG_CRIT, "Packet too small for answer");
		return NULL;
	}

	if ((question = malloc(sizeof *question)) == NULL) {
		fdf_filter_log(handle, LOG_CRIT, "Memory allocation failure");
		abort();
	}

	question->c.qname = qname;
	question->c.size = qname_size + 4;
	question->c.qtype = mdns_get_unaligned_u16(sect + qname_size);
	question->c.qclass = mdns_get_unaligned_u16(sect + qname_size + 2);

	return question;
}

static struct mdns_rr *mdns_parse_rr(const uintptr_t handle,
				     const union mdns_pkt *pkt,
				     const size_t pkt_size,
				     unsigned int offset)
{
	struct mdns_rr *rr;
	const uint8_t *sect;
	unsigned int name_size;
	char *name;
	uint16_t rdlength;

	if (pkt_size < offset + 11) {  /* root + fixed size members */
		fdf_filter_log(handle, LOG_CRIT, "Packet too small for RR");
		return NULL;
	}

	sect = pkt->raw + offset;

	name_size = mdns_parse_name(handle, sect, pkt, pkt_size, &name);
	if (name_size == 0)
		return NULL;

	if (pkt_size < offset + name_size + 10) {
		fdf_filter_log(handle, LOG_CRIT, "Packet too small for RR");
		return NULL;
	}

	rdlength = mdns_get_unaligned_u16(sect + name_size + 8);

	if (pkt_size < offset + name_size + 10 + rdlength) {
		fdf_filter_log(handle, LOG_CRIT, "Packet too small for RR");
		return NULL;
	}

	if ((rr = malloc(sizeof *rr)) == NULL) {
		fdf_filter_log(handle, LOG_CRIT, "Memory allocation failure");
		return NULL;
	}

	rr->c.name = name;
	rr->c.size = name_size + 10 + rdlength;
	rr->ttl = mdns_get_unaligned_u32(sect + name_size + 4);
	rr->c.type = mdns_get_unaligned_u16(sect + name_size);
	rr->c.class = mdns_get_unaligned_u16(sect + name_size + 2);
	rr->rdlength = rdlength;

	return rr;
}

/*
 * Return values:
 *	-1: error
 *	 0: success
 *	 1: success (unicast response requested)
 */
static int mdns_parse_questions(const uintptr_t handle,
				const union mdns_pkt *pkt,
				const size_t pkt_size, const uintptr_t in_netif)
{
	unsigned int offset;
	uint16_t qdcount;
	struct mdns_question *question;
	struct timespec now;
	_Bool qu;

	if (clock_gettime(CLOCK_BOOTTIME, &now) < 0) {
		fdf_filter_log(handle, LOG_CRIT,
			       "clock_gettime(CLOCK_BOOTTIME): %m");
		abort();
	}

	mdns_remove_old(handle, now.tv_sec);
	qdcount = ntohs(pkt->qdcount);
	offset = MDNS_DNS_HDR_SIZE;
	qu = 0;

	while (qdcount-- > 0) {

		question = mdns_parse_question(handle, pkt, pkt_size, offset);
		if (question == NULL)
			return -1;

		offset += question->c.size;

		if ((question->c.qclass & ~MDNS_QCLASS_QU) != MDNS_CLASS_IN) {
			fdf_filter_log(handle, LOG_DEBUG,
				       "Ignoring question with class %s",
				       mdns_class_name(question->c.qclass));
			mdns_free_question(question);
			continue;
		}

		if (question->c.qclass & MDNS_QCLASS_QU)
			qu = 1;

		fdf_filter_log(handle, LOG_DEBUG,
			       "\tquestion: IN %10s\t%s (%s)",
			       mdns_type_name(question->c.qtype),
			       question->c.qname,
			       (question->c.qclass & MDNS_QCLASS_QU)
								? "QU" : "QM");

		mdns_add_question(question, in_netif, now.tv_sec);
	}

	return qu;
}

static _Bool mdns_parse_answers(const uintptr_t handle,
				const union mdns_pkt *pkt,
				const size_t pkt_size,
				uintptr_t *const fwd_netif_out)
{
	unsigned int offset;
	uint16_t ancount;
	struct mdns_rr *answer;
	struct timespec now;
	const struct savl_node *node;
	const struct mdns_question *question;

	if (clock_gettime(CLOCK_BOOTTIME, &now) < 0) {
		fdf_filter_log(handle, LOG_CRIT,
			       "clock_gettime(CLOCK_BOOTTIME): %m");
		abort();
	}

	mdns_remove_old(handle, now.tv_sec);
	ancount = ntohs(pkt->ancount);
	offset = MDNS_DNS_HDR_SIZE;

	while (ancount-- > 0) {

		answer = mdns_parse_rr(handle, pkt, pkt_size, offset);
		if (answer == NULL)
			return 0;

		offset += answer->c.size;

		if ((answer->c.class & ~MDNS_CLASS_CF) != MDNS_CLASS_IN) {
			fdf_filter_log(handle, LOG_DEBUG,
				       "Ignoring answer with class %s",
				       mdns_class_name(answer->c.class));
			mdns_free_rr(answer);
			continue;
		}

		fdf_filter_log(handle, LOG_DEBUG, "\tanswer: IN %10s\t%s",
			       mdns_type_name(answer->c.type), answer->c.name);

		node = savl_get(mdns_questions, mdns_question_cmp,
				(union savl_key){ .p = &answer->c });

		if (node == NULL) {
			answer->c.type = MDNS_TYPE_ANY;
			node = savl_get(mdns_questions, mdns_question_cmp,
					(union savl_key){ .p = &answer->c });
		}

		if (node == NULL) {
			fdf_filter_log(handle, LOG_DEBUG,
				       "  No matching query found; ignoring");
			mdns_free_rr(answer);
			continue;
		}

		question = MDNS_QUESTION_FROM_NODE(node);

		fdf_filter_log(handle, LOG_DEBUG,
			       "  Found match; forwarding to %s",
			       fdf_filter_netif_name(handle, question->netif));

		*fwd_netif_out = question->netif;
		mdns_free_rr(answer);
		break;
	}

	return 1;
}

static uint8_t mdns_match_query(const uintptr_t handle, const uintptr_t flags,
				const struct sockaddr_storage *const src,
				const union mdns_pkt *const pkt,
				const size_t pkt_size, const uintptr_t in_netif)
{
	char buf[FDF_FILTER_SA6_LEN];

	if (pkt->ancount > 0) {
		fdf_filter_sock_addr(handle, src, buf, sizeof buf);
		fdf_filter_log(handle, LOG_WARNING,
			       "Query from %s contains > 0 answer resources",
			       buf);
		return FDF_FILTER_DROP_NOW;
	}

	if (mdns_mode == MDNS_MODE_STATELESS)
		return FDF_FILTER_PASS;

	switch (mdns_parse_questions(handle, pkt, pkt_size, in_netif)) {

		case -1:	return FDF_FILTER_DROP_NOW;

		case  1:	if (flags & MDNS_FLAG_CHAINED)
					return FDF_FILTER_PASS_NOW;

		/* fallthrough */
		case  0:	return FDF_FILTER_PASS;

		default:	abort();  /* Suppress compiler warning */
	}
}

static uint8_t mdns_match_response(const uintptr_t handle,
				   const struct sockaddr_storage *const src,
				   const union mdns_pkt *const pkt,
				   const size_t pkt_size,
				   uintptr_t *const fwd_netif_out)
{
	char buf[FDF_FILTER_SA6_LEN];

	if (pkt->qdcount > 0) {
		fdf_filter_sock_addr(handle, src, buf, sizeof buf);
		fdf_filter_log(handle, LOG_WARNING,
			       "Response from %s contains > 0 answer resources",
			       buf);
		return FDF_FILTER_DROP_NOW;
	}

	if (mdns_mode == MDNS_MODE_STATELESS)
		return FDF_FILTER_PASS;

	*fwd_netif_out = 0;

	if (mdns_parse_answers(handle, pkt, pkt_size, fwd_netif_out) == 0)
		return FDF_FILTER_DROP_NOW;

	return (*fwd_netif_out == 0) ? FDF_FILTER_DROP : FDF_FILTER_PASS;
}

static uint8_t mdns_match(const uintptr_t handle,
			  const struct sockaddr_storage *restrict const src,
			  const struct sockaddr_storage *restrict dest
							__attribute__((unused)),
			  const void *restrict const raw_pkt,
			  const size_t pkt_size, const uintptr_t in_netif,
			  uintptr_t *const fwd_netif_out)
{
	char buf[FDF_FILTER_SA6_LEN];
	const union mdns_pkt *pkt;
	uintptr_t flags;

	if (pkt_size < sizeof(union mdns_pkt)) {
		fdf_filter_sock_addr(handle, src, buf, sizeof buf);
		fdf_filter_log(handle, LOG_WARNING,
			       "Packet from %s too small (%zd bytes)",
			       buf, pkt_size);
	}

	pkt = FDF_FILTER_PKT_AS(union mdns_pkt, raw_pkt);
	flags = fdf_filter_get_data(handle).u;

	if (flags & MDNS_FLAG_FWD_RESP) {

		if (mdns_is_query(pkt)) {
			fdf_filter_log(handle, LOG_DEBUG,
				       "  Dropping query packet");
			return FDF_FILTER_DROP;
		}

		return mdns_match_response(handle, src, pkt,
					   pkt_size, fwd_netif_out);
	}
	else {
		if (mdns_is_answer(pkt)) {
			fdf_filter_log(handle, LOG_DEBUG,
				       "  Dropping answer packet");
			return (flags & MDNS_FLAG_CHAINED)
					? FDF_FILTER_DROP_NOW : FDF_FILTER_DROP;
		}

		return mdns_match_query(handle, flags, src,
					pkt, pkt_size, in_netif);
	}
}

static _Bool mdns_parse_mode(const uintptr_t handle, const char *const arg)
{
	if (mdns_mode_set) {
		fdf_filter_log(handle, LOG_ERR, "mDNS filter mode already set");
		return 1;
	}

	mdns_mode_set = 1;

	if (strcmp(arg, "stateless") == 0) {
		mdns_mode = MDNS_MODE_STATELESS;
		fdf_filter_log(handle, LOG_DEBUG,
			       "mDNS filter mode set to STATELESS");
		return 0;
	}

	if (strcmp(arg, "stateful") == 0) {
		mdns_mode = MDNS_MODE_STATEFUL;
		fdf_filter_log(handle, LOG_DEBUG,
			       "mDNS filter mode set to STATEFUL");
		return 0;
	}

	fdf_filter_log(handle, LOG_ERR, "Unknown mDNS filter mode: %s", arg);
	return 1;
}

static _Bool mdns_parse_qlife(const uintptr_t handle, const char *const arg)
{
	long qlife;
	char *endptr;

	if (mdns_qlife_set) {
		fdf_filter_log(handle, LOG_ERR, "mDNS query life already set");
		return 1;
	}

	mdns_qlife_set = 1;

	/* Don't accept leading whitespace or sign */
	if (*arg < '0' || *arg > '9') {
		fdf_filter_log(handle, LOG_ERR, "Invalid query life: %s", arg);
		return 1;
	}

	errno = 0;
	qlife = strtol(arg, &endptr, 10);
	if (errno != 0 || *endptr != 0) {
		fdf_filter_log(handle, LOG_ERR, "Invalid query life: %s", arg);
		return 1;
	}

	if (qlife < 30 || qlife > 3600) {
		fdf_filter_log(handle, LOG_ERR,
			       "Query life out of range (30-3600): %s", arg);
		return 1;
	}

	mdns_query_life = qlife;
	return 1;
}

static _Bool mdns_parse_fwd(const uintptr_t handle,
			    const char *restrict const arg,
			    uintptr_t *const flags)
{
	if (*flags & MDNS_FLAG_FWD_SET) {
		fdf_filter_log(handle, LOG_ERR,
			       "Instance forward type already set");
		return 1;
	}

	if (strcmp(arg, "queries") == 0) {
		*flags |= MDNS_FLAG_FWD_SET;  /* Flags initialized to 0 */
		fdf_filter_log(handle, LOG_DEBUG,
			       "Instance forward type set to QUERIES");
		return 0;
	}

	if (strcmp(arg, "responses") == 0) {
		*flags |= (MDNS_FLAG_FWD_RESP | MDNS_FLAG_FWD_SET);
		fdf_filter_log(handle, LOG_DEBUG,
			       "Instance forward type set to RESPONSES");
		return 0;
	}

	fdf_filter_log(handle, LOG_ERR, "Unknown forward type: %s", arg);
	return 1;
}

static _Bool mdns_parse_chained(const uintptr_t handle,
				const char *restrict const arg,
				uintptr_t *const flags)
{
	if (*flags & MDNS_FLAG_CHAINED_SET) {
		fdf_filter_log(handle, LOG_ERR,
			       "Instance chained mode already set");
		return 1;
	}

	if (strcasecmp(arg, "yes") == 0 || strcasecmp(arg, "true") == 0) {
		*flags |= (MDNS_FLAG_CHAINED | MDNS_FLAG_CHAINED_SET);
		fdf_filter_log(handle, LOG_DEBUG,
			       "Instanced set to CHAINED mode");
		return 0;
	}

	if (strcasecmp(arg, "no") == 0 || strcasecmp(arg, "false") == 0) {
		*flags |= MDNS_FLAG_CHAINED_SET;  /* Flags initialized to 0 */
		fdf_filter_log(handle, LOG_ERR,
			       "Instance set to UNCHAINED mode");
		return 0;
	}

	fdf_filter_log(handle, LOG_ERR, "Unknown chained mode: %s", arg);
	return 1;
}

static _Bool mdns_init(const uintptr_t handle,
		       const int argc, const char *const *const argv)
{
	uintptr_t flags;
	_Bool err;
	int i;

	if (argc < 3 || argc > 6) {
		fdf_filter_log(handle, LOG_ERR,
			       "%s requires between 1 and 4 arguments",
			       argv[1]);
		return 0;
	}

	flags = 0;

	for (i = 2; i < argc; ++i) {

		err = 0;

		if (strncmp(argv[i], "mode=", 5) == 0) {
			err = mdns_parse_mode(handle, argv[i] + 5);
		}
		else if (strncmp(argv[i], "query_life=", 11) == 0) {
			err = mdns_parse_qlife(handle, argv[i] + 11);
		}
		else if (strncmp(argv[i], "forward=", 8) == 0) {
			err = mdns_parse_fwd(handle, argv[i] + 8, &flags);
		}
		else if (strncmp(argv[i], "chained=", 8) == 0) {
			err = mdns_parse_chained(handle, argv[i] + 8, &flags);
		}
		else {
			fdf_filter_log(handle, LOG_ERR,
				       "Unknown argument: %s", argv[i]);
			return 0;
		}

		if (err)
			return 0;
	}

	if (!(flags & MDNS_FLAG_FWD_SET)) {
		fdf_filter_log(handle, LOG_ERR,
			       "forward={queries|responses} argument required");
		return 0;
	}

	fdf_filter_set_data(handle, (union fdf_filter_data){ .u = flags });

	return 1;
}

static void mdns_cleanup(const uintptr_t handle __attribute__((unused)))
{
	mdns_free_questions();
}

FDF_FILTER(mdns_init, mdns_match, mdns_cleanup);

// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	fdfd.h - FDF daemon internal header
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#ifndef FDFD_H_INCLUDED
#define FDFD_H_INCLUDED

#include "fdf-filter.h"

#include <json-c/json.h>
#include <net/if.h>
#include <netinet/in.h>
#include <savl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>


/*
 *
 *	Constants
 *
 */

#define FDF_EPOLL_EVENT_MAX	5
#define FDF_PKT_BUF_SIZE	1536

/*
 *
 *	Data types
 *
 */

union fdf_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
	struct sockaddr_storage	ss;
};

struct fdf_netif {
	char			name[IFNAMSIZ];
	int			index;
	struct savl_node	node;
};

struct fdf_filter {
	const struct fdf_filter_info	*info;
	struct savl_node		name_node;
	struct savl_node		so_node;
	void				*so_handle;
	union fdf_filter_data		instance_data;
	int				argc;
	union {
		char			*argv[3];	/* may have more */
		struct {
			const char	*name;  	/* argv[0] */
			const char	*file;		/* argv[1] */
		};
	};
};

struct fdf_match {
	char				*name;
	union fdf_sockaddr		sa;
	struct savl_node		name_node;
	struct savl_node		tuple_node;
	unsigned int			num_filters;
	struct fdf_filter		*filters[];
};

struct fdf_listener {
	const struct fdf_netif	*listen_netif;
	const struct fdf_match	*match;
	struct fdf_listener	*next;
	int			fd;
	unsigned int		num_fwd_netifs;
	struct fdf_netif	*fwd_netifs[];
};


/*
 *
 *	Global variables
 *
 */

extern _Bool fdf_debug;
extern _Bool fdf_pktlog;
extern _Bool fdf_use_syslog;
extern const char *fdf_cfg_json_name;
extern volatile sig_atomic_t fdf_exit_flag;


/*
 *
 *	Logging
 *
 */

__attribute__((format(printf, 2, 3)))
void fdf_log(const int level, const char *const format, ...);

/* Preprocessor dance to "stringify" an expanded macro value (e.g. __LINE__) */
#define FDF_STR_RAW(x)		#x
#define	FDF_STR(x)		FDF_STR_RAW(x)

/* Expands to a message preamble which specifies file & line */
#define FDF_LOCATION		__FILE__ ":" FDF_STR(__LINE__) ": "

/* Expands to syslog priority & full message preamble */
#define FDF_LOG_HDR(lvl)	LOG_ ## lvl, #lvl ": " FDF_LOCATION

/* Debug messages are logged at LOG_INFO priority to avoid syslog filtering */
#define FDF_DEBUG_HDR		LOG_INFO, "DEBUG: " FDF_LOCATION
#define FDF_DEBUG(fmt, ...)						\
	do {								\
		if (fdf_debug)						\
			fdf_log(FDF_DEBUG_HDR fmt, ##__VA_ARGS__);	\
	}								\
	while (0)

/* Print/log a message at the given priority */
#define FDF_INFO(fmt, ...)	fdf_log(FDF_LOG_HDR(INFO) fmt, ##__VA_ARGS__)
#define FDF_NOTICE(fmt, ...)	fdf_log(FDF_LOG_HDR(NOTICE) fmt, ##__VA_ARGS__)
#define FDF_WARNING(fmt, ...)	fdf_log(FDF_LOG_HDR(WARNING) fmt, ##__VA_ARGS__)
#define FDF_ERR(fmt, ...)	fdf_log(FDF_LOG_HDR(ERR) fmt, ##__VA_ARGS__)
#define FDF_CRIT(fmt, ...)	fdf_log(FDF_LOG_HDR(CRIT) fmt, ##__VA_ARGS__)
#define FDF_ALERT(fmt, ...)	fdf_log(FDF_LOG_HDR(ALERT) fmt, ##__VA_ARGS__)
#define FDF_EMERG(fmt, ...)	fdf_log(FDF_LOG_HDR(EMERG) fmt, ##__VA_ARGS__)

/* Print/log an unexpected internal error and abort */
#define FDF_ABORT(...)		do { FDF_CRIT(__VA_ARGS__); abort(); } while (0)

#define FDF_ASSERT(expr)						\
	do {								\
		if (!(expr))						\
			FDF_ABORT("Assertion failed: " #expr);		\
	} while (0)

/* Print a fatal error and exit immediately */
#define FDF_FATAL(...)							\
	do {								\
		FDF_ERR(__VA_ARGS__);					\
		exit(EXIT_FAILURE);					\
	} while (0)

#define FDF_PFATAL(msg)		FDF_FATAL("%s: %m", msg)

#define FDF_PKTLOG(...)							\
	do {								\
		if (fdf_pktlog)						\
			FDF_INFO(__VA_ARGS__);				\
	} while (0)

#define FDF_PKTDBG(...)							\
	do {								\
		if (fdf_pktlog)						\
			FDF_DEBUG(__VA_ARGS__);				\
	} while (0)


void *fdf_zalloc(const size_t size, const char *const file, const int line);
#define FDF_ZALLOC(size)	fdf_zalloc(size, __FILE__, __LINE__)

#define FDF_VZALLOC(size, nmemb, type)					\
	FDF_ZALLOC((size) + (nmemb) * sizeof(type))


static inline _Bool fdf_is_mcast(const struct in_addr addr)
{
	/* IPv4 multicast range is 224.0.0.0/4 */
	return (htonl(addr.s_addr) & 0xf0000000) == 0xe0000000;
}

static inline _Bool fdf_is_bcast(const struct in_addr addr)
{
	/* Byte order doesn't matter; address is all 1s (255.255.255.255) */
	return addr.s_addr == INADDR_BROADCAST;
}

static inline int fdf_ptr_cmp(const void *const p1, const void *const p2)
{

	if ((uintptr_t)p1 < (uintptr_t)p2)
		return -1;
	else if ((uintptr_t)p1 > (uintptr_t)p2)
		return 1;
	else
		return 0;
}

static inline char *fdf_strdup(const char *const s)
{
	size_t len;
	char *copy;

	len = strlen(s);
	copy = FDF_ZALLOC(len + 1);
	memcpy(copy, s, len);

	return copy;
}

struct fdf_netif *fdf_get_netif(const char *const netif_name);
struct fdf_match *fdf_get_match(const char *const match_name);
struct fdf_match *fdf_try_add_match(struct fdf_match *const match);
void fdf_parse_argv(const int argc, char **const argv);
void fdf_parse_config(void);
void fdf_free_netifs(void);
void fdf_free_matches(void);
struct fdf_filter *fdf_get_filter(const char *const name);
void fdf_filter_add(struct fdf_filter *const filter);
void fdf_free_filters(void);
void fdf_listener_add(struct fdf_listener *const new);
void fdf_free_listeners(const int epfd);
int fdf_init_listeners(void);
void fdf_process(const struct fdf_listener *const l);
void fdf_sender_init(void);
void fdf_sender_close(void);
void fdf_signal_setup(sigset_t *const oldmask);

void fdf_load_filter(const char *const name, const char *const file,
		     struct json_object *const args, const size_t num_args);

_Bool fdf_filter_match(const struct fdf_listener *const lstnr,
		       const struct sockaddr_storage *const src,
		       const void *restrict const pkt, const size_t pkt_size,
		       const struct fdf_netif **fwd_netif_out);

#endif	/* FDFD_H_INCLUDED */

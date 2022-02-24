// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	filter.c - Filter plug-ins
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

// SPDX-License-Identifier: GPL-2.0-or-later

#include "fdfd.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>

/* See FDF_FILTER_{PASS|DROP}_{FORCE|NOW} & FDF_FILTER_PASS in fdf-filter.h */
#define FDF_FILTER_NOW		4  /* binary: 100 */
#define FDF_FILTER_FORCE	2  /* binary: 010 */

#define FDF_FILTER_FROM_NAME_NODE(_n) \
	((_n) ? SAVL_NODE_CONTAINER((_n), struct fdf_filter, name_node) : NULL)

#define FDF_FILTER_FROM_SO_NODE(_n) \
	((_n) ? SAVL_NODE_CONTAINER((_n), struct fdf_filter, so_node) : NULL)

static struct savl_node *fdf_filters_by_name = NULL;
static struct savl_node *fdf_filters_by_so = NULL;

static struct fdf_filter *fdf_current;
static _Bool fdf_matching = 0;

static int fdf_filter_cmp_name(const union savl_key key,
			       const struct savl_node *const node)
{
	return strcmp(key.p, FDF_FILTER_FROM_NAME_NODE(node)->name);
}

static int fdf_filter_cmp_so(const union savl_key key,
			     const struct savl_node *const node)
{
	return fdf_ptr_cmp(key.p, FDF_FILTER_FROM_SO_NODE(node)->so_handle);
}

struct fdf_filter *fdf_get_filter(const char *const name)
{
	union savl_key key;

	key.p = name;
	return FDF_FILTER_FROM_NAME_NODE(savl_get(fdf_filters_by_name,
						  fdf_filter_cmp_name, key));
}

void fdf_filter_add_current(void)
{
	union savl_key key;
	const struct savl_node *existing;

	key.p = fdf_current->name;
	existing = savl_try_add(&fdf_filters_by_name, fdf_filter_cmp_name,
				key, &fdf_current->name_node);
	FDF_ASSERT(existing == NULL);  /* JSON format should ensure this */

	if (fdf_current->so_handle != NULL) {
		key.p = fdf_current->so_handle;
		existing = savl_try_add(&fdf_filters_by_so, fdf_filter_cmp_so,
					key, &fdf_current->so_node);
		FDF_ASSERT(existing == NULL);
	}
}

static void fdf_free_filter(struct savl_node *const node)
{
	struct fdf_filter *filter;
	int i;

	filter = FDF_FILTER_FROM_NAME_NODE(node);

	if (filter->info->cleanup_fn != NULL) {
		fdf_current = filter;
		filter->info->cleanup_fn((uintptr_t)filter);
	}

	if (filter->so_handle != NULL) {
		if (dlclose(filter->so_handle) != 0) {
			FDF_ABORT("Error closing shared object (%s): %s",
				  filter->file, dlerror());
		}
	}

	for (i = 0; i < filter->argc; ++i)
		free(filter->argv[i]);

	free(filter);
}

void fdf_free_filters(void)
{
	savl_free(&fdf_filters_by_name, fdf_free_filter);
}

/* Check a pointer for NULL, without triggering a nonnull-compare warning */
__attribute__((always_inline))
static inline _Bool fdf_is_null(const void *const p)
{
	return p == NULL;
}

void fdf_filter_register(const struct fdf_filter_info *info)
{
	if (fdf_is_null(info)) {
		FDF_FATAL("Filter (%s) invalid registration: NULL info",
			  fdf_current->name);
	}

	if (info->api_ver != FDF_FILTER_API_VER) {
		FDF_FATAL("Filter (%s) invalid API version: "
				"expected 0x%016" PRIx64 ", got 0x%016" PRIx64,
			  fdf_current->name, FDF_FILTER_API_VER, info->api_ver);
	}

	if (info->match_fn == NULL) {
		FDF_FATAL("Filter (%s) invalid registration: NULL match_fn",
			  fdf_current->name);
	}

	fdf_current->info = info;
}

static void fdf_init_current(void)
{
	fdf_filter_init_fn init_fn;
	_Bool init_result;

	init_fn = fdf_current->info->init_fn;

	if (init_fn == NULL) {

		if (fdf_current->argc > 2) {
			FDF_FATAL("Cannot pass arguments to filter (%s): "
						"filter has no init function",
				  fdf_current->name);
		}

		return;
	}
	else {
		init_result = init_fn((uintptr_t)fdf_current, fdf_current->argc,
				     (const char *const *)fdf_current->argv);
		if (!init_result) {
			FDF_FATAL("Filter (%s) initialization failed",
				  fdf_current->name);
		}
	}
}

void fdf_load_filter(const char *const name, const char *const file,
		     struct json_object *const args, const size_t num_args)
{
	const struct savl_node *existing;
	union savl_key key;
	const char *arg;
	size_t i;

	fdf_current = FDF_VZALLOC(sizeof *fdf_current, num_args, char *);

	fdf_current->argc = 2 + num_args;
	fdf_current->name = fdf_strdup(name);  /* fdf_current->argv[0] */
	fdf_current->file = fdf_strdup(file);  /* fdf_current->argv[1] */

	for (i = 0; i < num_args; ++i) {
		arg =json_object_get_string(json_object_array_get_idx(args, i));
		fdf_current->argv[2 + i] = fdf_strdup(arg);
	}

	fdf_current->so_handle = dlopen(file, RTLD_NOW | RTLD_NOLOAD);
	if (fdf_current->so_handle == NULL) {

		fdf_current->so_handle = dlopen(file, RTLD_NOW | RTLD_LOCAL);
		if (fdf_current->so_handle == NULL) {
			FDF_FATAL("Error loading filter (%s): %s",
				  name, dlerror());
		}

		if (fdf_current->info == NULL)
			FDF_FATAL("Filter (%s) did not register", name);
	}
	else {
		if (dlclose(fdf_current->so_handle) != 0) {
			FDF_ABORT("Error closing shared object (%s): %s",
				  file, dlerror());
		}

		key.p = fdf_current->so_handle;
		existing = savl_get(fdf_filters_by_so, fdf_filter_cmp_so, key);
		if (existing == NULL) {
			FDF_FATAL("Shared object (%s) was already loaded, but "
					"it did not register as an NDF filter",
				  file);
		}

		fdf_current->info = FDF_FILTER_FROM_SO_NODE(existing)->info;
		fdf_current->so_handle = NULL;
	}

	fdf_init_current();
	fdf_filter_add_current();

	if (num_args > 0) {
		FDF_INFO("Loaded filter (%s) from %s %s", name, file,
			 json_object_get_string(args));
	}
	else {
		FDF_INFO("Loaded filter (%s) from %s", name, file);
	}
}

_Bool fdf_filter_match(const struct fdf_listener *const lstnr,
		       const struct sockaddr_storage *const src,
		       const void *restrict const pkt, const size_t pkt_size,
		       const struct fdf_netif **fwd_netif_out)
{
	static const char *const result_names[] = {
		[FDF_FILTER_DROP_NOW]	= "FDF_FILTER_DROP_NOW",
		[FDF_FILTER_DROP_FORCE]	= "FDF_FILTER_DROP_FORCE",
		[FDF_FILTER_DROP]	= "FDF_FILTER_DROP",
		[FDF_FILTER_PASS]	= "FDF_FILTER_PASS",
		[FDF_FILTER_PASS_FORCE]	= "FDF_FILTER_PASS_FORCE",
		[FDF_FILTER_PASS_NOW]	= "FDF_FILTER_PASS_NOW"
	};

	fdf_filter_match_fn match_fn;
	unsigned int i;
	uint8_t result, state;
	uintptr_t fwd_netif;

	fdf_matching = 1;
	state = FDF_FILTER_PASS;
	*fwd_netif_out = NULL;

	for (i = 0; i < lstnr->match->num_filters; ++i) {

		fdf_current = lstnr->match->filters[i];
		match_fn = fdf_current->info->match_fn;
		fwd_netif = 0;

		result = match_fn((uintptr_t)fdf_current, src,
				  &lstnr->match->sa.ss, pkt, pkt_size,
				  (uintptr_t)lstnr->listen_netif, &fwd_netif);

		if (fwd_netif != 0) {

			if (*fwd_netif_out != NULL) {
				FDF_FATAL("Filter (%s:%s:%s) changed packet "
						"output interface, which was "
						"set by an earlier filter",
					  lstnr->listen_netif->name,
					  lstnr->match->name,
					  lstnr->match->filters[i]->name);
			}

			*fwd_netif_out = (struct fdf_netif *)fwd_netif;

			FDF_PKTDBG("  Filter (%s) set output interface to %s",
				   lstnr->match->filters[i]->name,
				   (*fwd_netif_out)->name);
		}

		if (result > FDF_FILTER_PASS_NOW) {
			FDF_FATAL("Invalid match function result (%" PRIu8
						") from filter (%s)",
				  result, fdf_current->name);
		}

		FDF_PKTDBG("  Filter (%s) returned %s",
			  fdf_current->name, result_names[result]);

		if (result & FDF_FILTER_NOW) {
			state = result;
			break;
		}

		if ((result & FDF_FILTER_FORCE) || !(state & FDF_FILTER_FORCE))
			state = result;
	}

	fdf_matching = 0;
	return state & 1;  /* pass/drop in low bit */
}

/*
 * 	Convenience functions for filters
 */

void fdf_filter_log(const uintptr_t handle, int priority,
		    const char *restrict const format, ...)
{
	static const char lvl_names[8][sizeof "WARNING"] = {
		[LOG_EMERG]	= "EMERG",
		[LOG_ALERT]	= "ALERT",
		[LOG_CRIT]	= "CRIT",
		[LOG_ERR]	= "ERR",
		[LOG_WARNING]	= "WARNING",  /* longest */
		[LOG_NOTICE]	= "NOTICE",
		[LOG_INFO]	= "INFO",
		[LOG_DEBUG]	= "DEBUG"
	};

	static char buf[200];

	const char *lvl_name;
	va_list ap;
	size_t len;

	FDF_ASSERT(handle == (uintptr_t)fdf_current);

	if (priority < 0 || priority > LOG_DEBUG) {
		FDF_WARNING("Invalid message priority (%d) from filter (%s); "
					"logging as LOG_INFO",
			    priority, fdf_current->name);
		lvl_name = "(unknown)";
		priority = LOG_INFO;
	}
	else {
		lvl_name = lvl_names[priority];
	}

	if (priority == LOG_DEBUG && !fdf_debug)
		return;

	if (fdf_matching && !fdf_pktlog && priority >= LOG_INFO)
		return;

	va_start(ap, format);
	len = vsnprintf(buf, sizeof buf, format, ap);
	va_end(ap);

	if (len >= sizeof buf) {
		FDF_WARNING("Message from filter (%s) too long; truncating",
			    fdf_current->name);
	}

	fdf_log(priority, "%s: %s: %s", lvl_name, fdf_current->name, buf);
}

static void fdf_ntos4(const struct sockaddr_in *const addr, char *const dst,
		      const size_t size)
{
	if (size < FDF_FILTER_SA4_LEN) {
		FDF_ABORT("Filter (%s) buffer too small "
					"for IPv4 socket address",
			  fdf_current->name);
	}

	if (inet_ntop(AF_INET, addr, dst, size) == NULL) {
		FDF_ABORT("Failed to format IPv4 address from filter (%s)",
			  fdf_current->name);
	}

	sprintf(dst + strlen(dst), ":%" PRIu16, ntohs(addr->sin_port));
}

static void fdf_ntos6(const struct sockaddr_in6 *const addr, char *const dst,
		      const size_t size)
{
	if (size < FDF_FILTER_SA6_LEN) {
		FDF_ABORT("Filter (%s) buffer too small "
					"for IPv6 socket address",
			  fdf_current->name);
	}

	*dst = '[';

	if (inet_ntop(AF_INET6, addr, dst + 1, size - 1) == NULL) {
		FDF_ABORT("Failed to format IPv6 address from filter (%s)",
			  fdf_current->name);
	}

	sprintf(dst + strlen(dst), "]:%" PRIu16, ntohs(addr->sin6_port));
}

const char *fdf_filter_sock_addr(const uintptr_t handle,
			const struct sockaddr_storage *restrict const addr,
			char *restrict const dst, const size_t size)
{
	FDF_ASSERT(handle == (uintptr_t)fdf_current);

	_Static_assert(offsetof(struct sockaddr_storage, ss_family) == 0,
		       "sockaddr_storage.ss_family offset incorrect");

	switch (*(const sa_family_t *)addr) {

		case AF_INET:
			fdf_ntos4((const struct sockaddr_in *)addr, dst, size);
			break;

		case AF_INET6:
			fdf_ntos6((const struct sockaddr_in6 *)addr, dst, size);
			break;

		default:
			FDF_ABORT("Unknown address family (%u) "
						"from filter (%s)",
				  *(const sa_family_t *)addr,
				  fdf_current->name);
	}

	return dst;
}

const char *fdf_filter_netif_name(const uintptr_t handle, const uintptr_t netif)
{
	FDF_ASSERT(handle == (uintptr_t)fdf_current);
	return ((const struct fdf_netif *)netif)->name;
}

void fdf_filter_set_data(const uintptr_t handle,
			 const union fdf_filter_data data)
{
	FDF_ASSERT(handle == (uintptr_t)fdf_current);
	fdf_current->instance_data = data;
}

union fdf_filter_data fdf_filter_get_data(const uintptr_t handle)
{
	FDF_ASSERT(handle == (uintptr_t)fdf_current);
	return fdf_current->instance_data;
}

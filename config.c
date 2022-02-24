// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	config.c - Configuration file parsing
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static char fdf_json_path[128] = { 0 };
static size_t fdf_jp_len = 0;

__attribute__((format(printf, 1, 2)))
static void fdf_jp_push(const char *restrict const format, ...)
{
	va_list ap;
	int len;

	va_start(ap, format);

	len = vsnprintf(fdf_json_path + fdf_jp_len,
		       sizeof fdf_json_path - fdf_jp_len, format, ap);
	if (len < 0)
		FDF_PFATAL("vsnprintf");

	if ((size_t)len >= sizeof fdf_json_path - fdf_jp_len) {
		FDF_FATAL("Configuration path too long: %s (truncated)",
			  fdf_json_path);
	}

	va_end(ap);
	fdf_jp_len += len;
}

static void fdf_jp_push_string(const char *const s)
{
	if (*s == 0)
		FDF_FATAL("Empty string at %s", fdf_json_path);

	if (strchr(s, '/') != NULL)
		FDF_FATAL("'/' character in string at %s/%s", fdf_json_path, s);

	fdf_jp_push("/%s", s);
}

static void fdf_jp_push_index(const size_t i)
{
	fdf_jp_push("/[%zu]", i);
}

static void fdf_jp_reset(void)
{
	fdf_jp_len = 0;
	fdf_json_path[0] = 0;
}

static void fdf_jp_pop(void)
{
	char *slash;

	slash = strrchr(fdf_json_path, '/');
	*slash = 0;
	fdf_jp_len = slash - fdf_json_path;
}

static void fdf_assert_json_type(struct json_object *const jo,
				 const enum json_type type)
{
	if (!json_object_is_type(jo, type)) {
		FDF_FATAL("Incorrect type for configuration item (%s): "
				"expected %s, found %s",
			  fdf_json_path, json_type_to_name(type),
			  json_type_to_name(json_object_get_type(jo)));
	}
}

static struct json_object *fdf_load_config(void)
{
	struct json_tokener *tok;
	struct json_object *cfg;
	struct stat st;
	char *json;
	int fd;

	if ((fd = open(fdf_cfg_json_name, O_RDONLY)) < 0)
		FDF_FATAL("Failed to open config (%s): %m", fdf_cfg_json_name);

	if (fstat(fd, &st) < 0)
		FDF_FATAL("Failed to stat config (%s): %m", fdf_cfg_json_name);

	json = mmap(NULL, st.st_size + 1,
		    PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (json == MAP_FAILED)
		FDF_FATAL("Failed to mmap config (%s): %m", fdf_cfg_json_name);

	if (close(fd) < 0)
		FDF_PFATAL("close");

	json[st.st_size] = 0;

	if ((tok = json_tokener_new()) == NULL)
		FDF_FATAL("Failed to create JSON parser");

	if ((cfg = json_tokener_parse_ex(tok, json, st.st_size)) == NULL) {
		FDF_FATAL("Failed to parse config (%s): %s", fdf_cfg_json_name,
			  json_tokener_error_desc(json_tokener_get_error(tok)));
	}

	json_tokener_free(tok);

	if (munmap(json, st.st_size + 1) < 0)
		FDF_PFATAL("munmap");

	if (!json_object_is_type(cfg, json_type_object)) {
		FDF_FATAL("Configuration file (%s) is not a JSON object",
			  fdf_cfg_json_name);
	}

	return cfg;
}

static json_object *fdf_json_get(struct json_object *const obj,
				 const char *const key, const _Bool required,
				 const enum json_type type)
{
	struct json_object *value;

	fdf_jp_push_string(key);

	if (!json_object_object_get_ex(obj, key, &value)) {
		if (required) {
			FDF_FATAL("Required onfiguration item (%s) not found",
				  fdf_json_path);
		}
		else {
			fdf_jp_pop();
			return NULL;
		}
	}

	fdf_assert_json_type(value, type);

	return value;
}

static void fdf_parse_listen_sa(union fdf_sockaddr *const sa,
				struct json_object *jo)
{
	struct json_object *port_jo;
	const char *addr;
	int32_t port;

	addr = json_object_get_string(fdf_json_get(jo, "addr", 1,
						   json_type_string));

	if (inet_aton(addr, &sa->sin.sin_addr) != 1) {
		FDF_FATAL("Invalid IPv4 address (%s) at %s",
			  addr, fdf_json_path);
	}

	if (!fdf_is_bcast(sa->sin.sin_addr)
				&& !fdf_is_mcast(sa->sin.sin_addr)) {
		FDF_FATAL("IPv4 address (%s) at %s "
					"is not broadcast or multicast",
			  addr, fdf_json_path);
	}

	sa->sin.sin_family = AF_INET;

	fdf_jp_pop();  /* pop "addr" */

	port_jo = fdf_json_get(jo, "port", 1, json_type_int);
	port = json_object_get_int(port_jo);

	if (port < 1 || port > 65535) {
		FDF_FATAL("Invalid UDP port (%s) at %s",
			  json_object_get_string(port_jo), fdf_json_path);
	}

	sa->sin.sin_port = htons(port);

	fdf_jp_pop();  /* pop "port" */
}

static void fdf_parse_match(const struct json_object_iterator *const iter)
{
	const char *name;
	struct json_object *jo, *filters, *filter_jo;
	struct fdf_match *match, *existing;
	struct fdf_filter *filter;
	size_t num_filters, i;

	name = json_object_iter_peek_name(iter);
	fdf_jp_push_string(name);
	FDF_DEBUG("Parsing match (%s)", fdf_json_path);

	jo = json_object_iter_peek_value(iter);
	fdf_assert_json_type(jo, json_type_object);

	filters = fdf_json_get(jo, "filters", 0, json_type_array);
	num_filters = filters == NULL ? 0 : json_object_array_length(filters);

	match = FDF_VZALLOC(sizeof *match, num_filters, struct fdf_filter *);
	match->name = fdf_strdup(name);
	match->num_filters = num_filters;

	for (i = 0; i < num_filters; ++i) {
		fdf_jp_push_index(i);
		filter_jo = json_object_array_get_idx(filters, i);
		fdf_assert_json_type(filter_jo, json_type_string);
		filter = fdf_get_filter(json_object_get_string(filter_jo));
		match->filters[i] = filter;
		fdf_jp_pop();  /* pop index */
	}

	if (num_filters > 0)
		fdf_jp_pop();  /* pop "filters" */

	fdf_parse_listen_sa(&match->sa, jo);

	if (num_filters == 0) {
		FDF_DEBUG("  %s: %s:%" PRIu16, match->name,
			inet_ntoa(match->sa.sin.sin_addr),
			ntohs(match->sa.sin.sin_port));
	}
	else {
		FDF_DEBUG("  %s: %s: %" PRIu16 " %s", match->name,
			  inet_ntoa(match->sa.sin.sin_addr),
			  ntohs(match->sa.sin.sin_port),
			  json_object_get_string(filters));
	}

	if ((existing = fdf_try_add_match(match)) != NULL) {
		FDF_FATAL("Match specification at %s is identical to %s",
			  fdf_json_path, existing->name);
	}
}

static void fdf_parse_matches(struct json_object *const cfg)
{
	struct json_object_iterator iter, end;
	struct json_object *matches;

	matches = fdf_json_get(cfg, "matches", 1, json_type_object);

	iter = json_object_iter_begin(matches);
	end = json_object_iter_end(matches);

	while (!json_object_iter_equal(&iter, &end)) {
		fdf_parse_match(&iter);
		fdf_jp_pop();  /* pop match name */
		json_object_iter_next(&iter);
	}
}

static
void fdf_assert_fwd_netif_ok(const size_t index,
			     struct fdf_netif *const *const fwd_netifs,
			     const struct fdf_netif *const listen_netif)
{
	size_t i;

	if (fwd_netifs[index] == listen_netif) {
		FDF_FATAL("Forward interface (%s) matches listen interface "
					"(%s) at configuration item (%s)",
			  fwd_netifs[index]->name, listen_netif->name,
			  fdf_json_path);
	}

	for (i = 0; i < index; ++i) {
		if (fwd_netifs[index] == fwd_netifs[i]) {
			FDF_FATAL("Duplicate interface (%s) "
						"at configuration item (%s)",
				  fwd_netifs[i]->name, fdf_json_path);
		}
	}
}

static void fdf_parse_listener(const struct json_object_iterator *const iter,
			       const struct fdf_netif *const listen_netif)
{
	const char *name;
	size_t num_fwd_netifs, i;
	struct json_object *value, *jo;
	const struct fdf_match *match;
	struct fdf_listener *listen;

	name = json_object_iter_peek_name(iter);
	if ((match = fdf_get_match(name)) == NULL)
		FDF_FATAL("Invalid match (%s) at %s", name, fdf_json_path);

	fdf_jp_push_string(name);
	FDF_DEBUG("Parsing listener (%s)", fdf_json_path);

	value = json_object_iter_peek_value(iter);
	fdf_assert_json_type(value, json_type_array);
	num_fwd_netifs = json_object_array_length(value);

	listen = FDF_VZALLOC(sizeof *listen,
			     num_fwd_netifs + 1, struct fdf_netif *);
	listen->listen_netif = listen_netif;
	listen->match = match;
	listen->num_fwd_netifs = num_fwd_netifs;

	for (i = 0; i < num_fwd_netifs; ++i) {

		fdf_jp_push_index(i);
		jo = json_object_array_get_idx(value, i);
		fdf_assert_json_type(jo, json_type_string);
		listen->fwd_netifs[i]
				= fdf_get_netif(json_object_get_string(jo));
		fdf_assert_fwd_netif_ok(i, listen->fwd_netifs, listen_netif);
		fdf_jp_pop();  /* pop index */
	}

	fdf_listener_add(listen);

	if (fdf_debug) {
		FDF_DEBUG("  %s:%s ==> %s", listen_netif->name, name,
			  json_object_get_string(value));
	}
}

static void fdf_parse_listen_netif(
			const struct json_object_iterator *const listen_iter)
{
	const char *name;
	struct fdf_netif *listen_netif;
	struct json_object *value;
	struct json_object_iterator iter, end;

	name = json_object_iter_peek_name(listen_iter);
	fdf_jp_push_string(name);
	FDF_DEBUG("Parsing listen interface (%s)", fdf_json_path);

	listen_netif = fdf_get_netif(name);

	value = json_object_iter_peek_value(listen_iter);
	fdf_assert_json_type(value, json_type_object);

	iter = json_object_iter_begin(value);
	end = json_object_iter_end(value);

	while (!json_object_iter_equal(&iter, &end)) {
		fdf_parse_listener(&iter, listen_netif);
		fdf_jp_pop();  /* pop match name */
		json_object_iter_next(&iter);
	}
}

static void fdf_parse_listen(struct json_object *const cfg)
{
	struct json_object_iterator iter, end;
	struct json_object *listen;

	listen = fdf_json_get(cfg, "listen", 1, json_type_object);

	iter = json_object_iter_begin(listen);
	end = json_object_iter_end(listen);

	while (!json_object_iter_equal(&iter, &end)) {
		fdf_parse_listen_netif(&iter);
		fdf_jp_pop(); /* pop listen interface name */
		json_object_iter_next(&iter);
	}
}

static void fdf_parse_filter(const struct json_object_iterator *const iter)
{
	const char *name;
	struct json_object *value, *file, *args;
	size_t num_args, i;

	name = json_object_iter_peek_name(iter);
	fdf_jp_push_string(name);
	FDF_DEBUG("Parsing filter (%s)", fdf_json_path);

	value = json_object_iter_peek_value(iter);
	fdf_assert_json_type(value, json_type_object);

	file = fdf_json_get(value, "file", 1, json_type_string);
	fdf_jp_pop();  /* pop "file" */

	args = fdf_json_get(value, "args", 0, json_type_array);

	if (args == NULL) {
		num_args = 0;
	}
	else {
		num_args = json_object_array_length(args);
		for (i = 0; i < num_args; ++i) {
			fdf_jp_push_index(i);
			fdf_assert_json_type(json_object_array_get_idx(args, i),
					     json_type_string);
			fdf_jp_pop();  /* pop index */
		}
		fdf_jp_pop();  /* pop "args" */
	}

	fdf_load_filter(name, json_object_get_string(file), args, num_args);
}

static void fdf_parse_filters(struct json_object *const cfg)
{
	struct json_object_iterator iter, end;
	struct json_object *filters;

	filters = fdf_json_get(cfg, "filters", 0, json_type_object);
	if (filters == NULL)
		return;

	iter = json_object_iter_begin(filters);
	end = json_object_iter_end(filters);

	while (!json_object_iter_equal(&iter, &end)) {
		fdf_parse_filter(&iter);
		fdf_jp_pop();  /* pop filter name */
		json_object_iter_next(&iter);
	}
}

void fdf_parse_config(void)
{
	struct json_object *cfg;

	cfg = fdf_load_config();

	fdf_parse_filters(cfg);
	fdf_jp_reset();

	fdf_parse_matches(cfg);
	fdf_jp_reset();

	fdf_parse_listen(cfg);

	FDF_ASSERT(json_object_put(cfg) == 1);
}

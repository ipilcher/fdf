// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *	FDF - Flexible Discovery Forwarder
 *
 *	match.c - Address, port & (optional) filter tuples
 *
 *	Copyright 2022 Ian Pilcher <arequipeno@gmail.com>
 */

#include "fdfd.h"

static struct savl_node *fdf_matches_by_name = NULL;
static struct savl_node *fdf_matches_by_tuple = NULL;

#define FDF_MATCH_FROM_NAME_NODE(_n) \
	((_n) ? SAVL_NODE_CONTAINER((_n), struct fdf_match, name_node) : NULL)

static int fdf_match_name_cmp(const union savl_key key,
			      const struct savl_node *const node)
{
	return strcmp(key.p, FDF_MATCH_FROM_NAME_NODE(node)->name);
}

#define FDF_MATCH_FROM_TUPLE_NODE(_n) \
	((_n) ? SAVL_NODE_CONTAINER((_n), struct fdf_match, tuple_node) : NULL)

static int fdf_match_tuple_cmp(const union savl_key key,
			       const struct savl_node *const node)
{
	const struct fdf_match *new, *existing;
	uint32_t new_ip, existing_ip;
	uint16_t new_port, existing_port;
	unsigned i;
	int result;

	new = key.p;
	existing = FDF_MATCH_FROM_TUPLE_NODE(node);

	FDF_ASSERT(new->sa.sin.sin_family == AF_INET);

	new_ip = ntohl(new->sa.sin.sin_addr.s_addr);
	existing_ip = ntohl(existing->sa.sin.sin_addr.s_addr);

	if (new_ip != existing_ip)
		return new_ip < existing_ip ? -1 : 1;

	new_port = ntohs(new->sa.sin.sin_port);
	existing_port = ntohs(existing->sa.sin.sin_port);

	if (new_port != existing_port)
		return new_port < existing_port ? -1 : 1;

	if (new->num_filters != existing->num_filters)
		return new->num_filters < existing->num_filters ? -1 : 1;

	for (i = 0; i < new->num_filters; ++i) {

		result = fdf_ptr_cmp(new->filters[i], existing->filters[i]);
		if (result != 0)
			return result;
	}

	return 0;
}

struct fdf_match *fdf_try_add_match(struct fdf_match *const match)
{
	union savl_key key;
	const struct savl_node *existing;

	key.p = match;
	//existing = savl_get(fdf_matches_by_tuple, fdf_match_tuple_cmp, key);
	existing = savl_try_add(&fdf_matches_by_tuple, fdf_match_tuple_cmp,
				key, &match->tuple_node);
	if (existing != NULL)
		return FDF_MATCH_FROM_TUPLE_NODE(existing);

	key.p = match->name;
	existing = savl_try_add(&fdf_matches_by_name, fdf_match_name_cmp,
				key, &match->name_node);
	FDF_ASSERT(existing == NULL);  /* JSON format should ensure this */



	return NULL;
}

struct fdf_match *fdf_get_match(const char *const match_name)
{
	union savl_key key;

	key.p = match_name;

	return FDF_MATCH_FROM_NAME_NODE(savl_get(fdf_matches_by_name,
						 fdf_match_name_cmp, key));
}

static void fdf_free_match(struct savl_node *const name_node)
{
	struct fdf_match *match = FDF_MATCH_FROM_NAME_NODE(name_node);

	savl_remove_node(&match->tuple_node, &fdf_matches_by_tuple);
	free(match->name);
	free(match);
}

void fdf_free_matches(void)
{
	savl_free(&fdf_matches_by_name, fdf_free_match);
}

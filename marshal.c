/*
 * marshal.c - SKS compatible marshalling routines
 *
 * Copyright 2011 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "charfuncs.h"
#include "keyid.h"
#include "keystructs.h"
#include "mem.h"
#include "parsekey.h"

void marshal_publickey(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				const struct openpgp_publickey *key)
{
	uint32_t len;
	struct openpgp_packet_list *packets = NULL, *list_end = NULL;
	struct buffer_ctx buf;

	buf.buffer = calloc(1, 1024);
	buf.size = 1024;
	buf.offset = 0;

	flatten_publickey((struct openpgp_publickey *) key, &packets,
			&list_end);
	write_openpgp_stream(buffer_putchar, &buf, packets);

	len = htonl(buf.offset);

	putchar_func(ctx, sizeof(len), &len);
	putchar_func(ctx, buf.offset, buf.buffer);

	free_packet_list(packets);
}

void marshal_skshash(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				const struct skshash *hash)
{
	uint32_t len;

	len = htonl(sizeof(hash->hash));

	putchar_func(ctx, sizeof(len), &len);
	putchar_func(ctx, sizeof(hash->hash), (void *) hash->hash);
}

struct skshash *unmarshal_skshash(size_t (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx)
{
	uint32_t len;
	struct skshash *hash;

	if (getchar_func(ctx, sizeof(len), &len) != sizeof(len)) {
		return NULL;
	}
	len = ntohl(len);
	if (len > sizeof(struct skshash)) {
		return NULL;
	}
	hash = calloc(sizeof(struct skshash), 1);
	if (getchar_func(ctx, len, hash->hash) != len) {
		free(hash);
		return NULL;
	}

	return hash;
}

void marshal_string(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				const char *string)
{
	uint32_t len, nlen;

	len = strlen(string);
	nlen = htonl(len);

	putchar_func(ctx, sizeof(nlen), &nlen);
	putchar_func(ctx, len, &string);
}

char *unmarshal_string(size_t (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx)
{
	uint32_t len;
	char *string;

	if (getchar_func(ctx, sizeof(len), &len) != sizeof(len)) {
		return NULL;
	}
	len = ntohl(len);
	string = malloc(len + 1);
	if (getchar_func(ctx, len, string) != len) {
		free(string);
		return NULL;
	}

	string[len] = 0;
	return string;
}

void marshal_array(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				void (*marshal_func)(size_t
					(*putchar_func)(void *ctx,
						size_t count, void *c),
					void *ctx, const void *item),
				void **array,
				int size)
{
	uint32_t len;
	int i;

	len = htonl(size);

	putchar_func(ctx, sizeof(len), &len);

	for (i = 0; i < size; i++) {
		marshal_func(putchar_func, ctx, array[i]);
	}
}

void **unmarshal_array(size_t (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				void *(*unmarshal_func)(size_t
					(*getchar_func)(void *ctx,
						size_t count, void *c),
					void *ctx),
				int *size)
{
	uint32_t len;
	void **array;
	int i;

	if (getchar_func(ctx, sizeof(len), &len) != sizeof(len)) {
		return NULL;
	}
	*size = ntohl(len);
	array = malloc(*size * sizeof(void *));
	for (i = 0; i < *size; i++) {
		array[i] = unmarshal_func(getchar_func, ctx);
	}

	return array;
}

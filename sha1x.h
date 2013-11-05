/*
 * sha1x.h - Double width SHA-1 as per PGP 5.5
 *
 * Copyright 2013 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#ifndef __SHA1X_H__
#define __SHA1X_H__

#include <stdbool.h>
#include <stdint.h>

#ifdef HAVE_NETTLE
#include <nettle/sha.h>
#else
#include "sha1.h"
#endif

#define SHA1X_DIGEST_SIZE (2 * SHA1_DIGEST_SIZE)

struct sha1x_ctx {
	struct sha1_ctx a, b, c, d;
	bool odd;
	unsigned char result[SHA1X_DIGEST_SIZE];
};

void sha1x_init(struct sha1x_ctx *ctx);
void sha1x_update(struct sha1x_ctx *ctx, unsigned length, const uint8_t *data);
void sha1x_digest(struct sha1x_ctx *ctx, unsigned length, uint8_t *digest);

#endif /* __SHA1X_H__ */

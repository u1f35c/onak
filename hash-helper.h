/*
 * hash-helper.h - Helper functions for calculating hashes
 *
 * Copyright Jonathan McDowell <noodles@earth.li>
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

#ifndef __HASH_HELPER_H__
#define __HASH_HELPER_H__

#include <stdint.h>

#include "build-config.h"

#ifdef HAVE_NETTLE
#include <nettle/md5.h>
#include <nettle/ripemd160.h>
#include <nettle/sha.h>
#else
#include "md5.h"
#include "sha1.h"
#endif

#include "onak.h"
#include "sha1x.h"

#define MAX_HASH_CHUNKS		8

struct onak_hash_ctx {
	uint8_t type;
	union {
		struct sha1_ctx sha1;
		struct sha1x_ctx sha1x;
		struct md5_ctx md5;
#ifdef HAVE_NETTLE
		struct ripemd160_ctx ripemd160;
		struct sha224_ctx sha224;
		struct sha256_ctx sha256;
		struct sha384_ctx sha384;
		struct sha512_ctx sha512;
#endif
	};
};

struct onak_hash_data {
	uint8_t hashtype;
	uint8_t chunks;
	size_t len[MAX_HASH_CHUNKS];
	uint8_t *data[MAX_HASH_CHUNKS];
};

onak_status_t onak_hash(struct onak_hash_data *data, uint8_t *hash);

#endif /* __HASH_HELPER_H__ */

/*
 * hash-helper.c - Helper functions for calculating hashes
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

#include "build-config.h"
#include "hash-helper.h"
#include "onak.h"
#include "openpgp.h"

onak_status_t onak_hash(struct onak_hash_data *data, uint8_t *hash)
{
	struct onak_hash_ctx hash_ctx;
	int i;

	if (data == NULL) {
		return ONAK_E_INVALID_PARAM;
	}

	if (data->chunks > MAX_HASH_CHUNKS) {
		return ONAK_E_INVALID_PARAM;
	}

	switch (data->hashtype) {
	case OPENPGP_HASH_MD5:
		md5_init(&hash_ctx.md5);
		for (i = 0; i < data->chunks; i++) {
			md5_update(&hash_ctx.md5, data->len[i], data->data[i]);
		}
		md5_digest(&hash_ctx.md5, MD5_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA1:
		sha1_init(&hash_ctx.sha1);
		for (i = 0; i < data->chunks; i++) {
			sha1_update(&hash_ctx.sha1, data->len[i], data->data[i]);
		}
		sha1_digest(&hash_ctx.sha1, SHA1_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA1X:
		sha1x_init(&hash_ctx.sha1x);
		for (i = 0; i < data->chunks; i++) {
			sha1x_update(&hash_ctx.sha1x, data->len[i], data->data[i]);
		}
		sha1x_digest(&hash_ctx.sha1x, SHA1X_DIGEST_SIZE, hash);
		break;
#ifdef HAVE_NETTLE
	case OPENPGP_HASH_RIPEMD160:
		ripemd160_init(&hash_ctx.ripemd160);
		for (i = 0; i < data->chunks; i++) {
			ripemd160_update(&hash_ctx.ripemd160, data->len[i],
				data->data[i]);
		}
		ripemd160_digest(&hash_ctx.ripemd160, RIPEMD160_DIGEST_SIZE,
			hash);
		break;
	case OPENPGP_HASH_SHA224:
		sha224_init(&hash_ctx.sha224);
		for (i = 0; i < data->chunks; i++) {
			sha224_update(&hash_ctx.sha224, data->len[i],
				data->data[i]);
		}
		sha224_digest(&hash_ctx.sha224, SHA224_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA256:
		sha256_init(&hash_ctx.sha256);
		for (i = 0; i < data->chunks; i++) {
			sha256_update(&hash_ctx.sha256, data->len[i],
				data->data[i]);
		}
		sha256_digest(&hash_ctx.sha256, SHA256_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA384:
		sha384_init(&hash_ctx.sha384);
		for (i = 0; i < data->chunks; i++) {
			sha384_update(&hash_ctx.sha384, data->len[i],
				data->data[i]);
		}
		sha384_digest(&hash_ctx.sha384, SHA384_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA512:
		sha512_init(&hash_ctx.sha512);
		for (i = 0; i < data->chunks; i++) {
			sha512_update(&hash_ctx.sha512, data->len[i],
				data->data[i]);
		}
		sha512_digest(&hash_ctx.sha512, SHA512_DIGEST_SIZE, hash);
		break;
#endif
	default:
		return ONAK_E_UNSUPPORTED_FEATURE;
	}

	return ONAK_E_OK;
}

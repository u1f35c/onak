/*
 * rsa.c - routines to check RSA hash signature combos not present in libnettle
 *
 * Copyright 2019 Jonathan McDowell <noodles@earth.li>
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

#include <string.h>

#ifdef HAVE_NETTLE
#include <nettle/ripemd160.h>
#include <nettle/rsa.h>
#include <nettle/sha.h>

#include "rsa.h"

const uint8_t ripemd160_prefix[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x24, 0x03, 0x02, 0x01,
	0x05, 0x00,
	0x04, 0x14
};

const uint8_t sha224_prefix[] = { 0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
	0x05, 0x00,
	0x04, 0x1c
};

const uint8_t sha384_prefix[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00,
	0x04, 0x3
};

int rsa_ripemd160_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t s)
{
	uint8_t buf[sizeof(ripemd160_prefix) + RIPEMD160_DIGEST_SIZE];

	memcpy(buf, ripemd160_prefix, sizeof(ripemd160_prefix));
	memcpy(buf + sizeof(ripemd160_prefix), digest, RIPEMD160_DIGEST_SIZE);

	return rsa_pkcs1_verify(key, sizeof(buf), buf, s);
}

int rsa_sha224_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t s)
{
	uint8_t buf[sizeof(sha224_prefix) + SHA224_DIGEST_SIZE];

	memcpy(buf, sha224_prefix, sizeof(sha224_prefix));
	memcpy(buf + sizeof(sha224_prefix), digest, SHA224_DIGEST_SIZE);

	return rsa_pkcs1_verify(key, sizeof(buf), buf, s);
}

int rsa_sha384_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t s)
{
	uint8_t buf[sizeof(sha384_prefix) + SHA384_DIGEST_SIZE];

	memcpy(buf, sha384_prefix, sizeof(sha384_prefix));
	memcpy(buf + sizeof(sha384_prefix), digest, SHA384_DIGEST_SIZE);

	return rsa_pkcs1_verify(key, sizeof(buf), buf, s);
}
#endif /* HAVE_NETTLE */

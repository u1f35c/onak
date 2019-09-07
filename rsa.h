/*
 * rsa.h - routines to check RSA hash signature combos not present in libnettle
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

#ifndef __RSA_H__
#define __RSA_H__

#ifdef HAVE_NETTLE
#include <string.h>

#include <nettle/ripemd160.h>
#include <nettle/rsa.h>
#include <nettle/sha.h>

int rsa_ripemd160_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t s);

int rsa_sha224_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t s);

int rsa_sha384_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t s);
#endif

#endif /* __RSA_H__ */

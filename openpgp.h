/*
 * openpgp.h - Defines directly related to OpenPGP RFC 4880
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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __OPENPGP_H__
#define __OPENPGP_H__

#define OPENPGP_PKALGO_RSA		1
#define OPENPGP_PKALGO_ELGAMAL		16
#define OPENPGP_PKALGO_DSA		17
#define OPENPGP_PKALGO_ELGAMAL_SIGN	20

#define OPENPGP_HASH_MD5		1
#define OPENPGP_HASH_SHA1		2
#define OPENPGP_HASH_RIPEMD160		3
#define OPENPGP_HASH_SHA256		8
#define OPENPGP_HASH_SHA384		9
#define OPENPGP_HASH_SHA512		10
#define OPENPGP_HASH_SHA224		11

#define OPENPGP_PACKET_SIGNATURE	2
#define OPENPGP_PACKET_PUBLICKEY	6
#define OPENPGP_PACKET_TRUST		12
#define OPENPGP_PACKET_UID		13
#define OPENPGP_PACKET_PUBLICSUBKEY	14
#define OPENPGP_PACKET_UAT		17

#define OPENPGP_SIGTYPE_BINARY		0x00
#define OPENPGP_SIGTYPE_TEXT		0x01
#define OPENPGP_SIGTYPE_KEY_REV		0x20
#define OPENPGP_SIGTYPE_SUBKEY_REV	0x28
#define OPENPGP_SIGTYPE_CERT_REV	0x30

#define OPENPGP_SIGSUB_CREATION		2
#define OPENPGP_SIGSUB_EXPIRY		3
#define OPENPGP_SIGSUB_EXPORTABLE	4
#define OPENPGP_SIGSUB_TRUSTSIG		5
#define OPENPGP_SIGSUB_REGEX		6
#define OPENPGP_SIGSUB_KEYEXPIRY	9
#define OPENPGP_SIGSUB_PREFSYM		11
#define OPENPGP_SIGSUB_ISSUER		16
#define OPENPGP_SIGSUB_NOTATION		20
#define OPENPGP_SIGSUB_PREFHASH		21
#define OPENPGP_SIGSUB_PREFCOMPRESS	22
#define OPENPGP_SIGSUB_KEYSERVER	23
#define OPENPGP_SIGSUB_PRIMARYUID	25
#define OPENPGP_SIGSUB_POLICYURI	26
#define OPENPGP_SIGSUB_KEYFLAGS		27

#endif /* __OPENPGP_H__ */

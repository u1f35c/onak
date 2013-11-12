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
#define OPENPGP_PKALGO_RSA_ENC		2
#define OPENPGP_PKALGO_RSA_SIGN		3
#define OPENPGP_PKALGO_ELGAMAL_ENC	16
#define OPENPGP_PKALGO_DSA		17
#define OPENPGP_PKALGO_EC		18
#define OPENPGP_PKALGO_ECDSA		19
#define OPENPGP_PKALGO_ELGAMAL_SIGN	20
#define OPENPGP_PKALGO_DH		21

#define OPENPGP_SYMALGO_PLAIN		0
#define OPENPGP_SYMALGO_IDEA		1
#define OPENPGP_SYMALGO_3DES		2
#define OPENPGP_SYMALGO_CAST5		3
#define OPENPGP_SYMALGO_BLOWFISH	4
#define OPENPGP_SYMALGO_SAFER_SK128	5	/* In RFC2440, not in RFC4880 */
#define OPENPGP_SYMALGO_DES_SK		6	/* In RFC2440, not in RFC4880 */
#define OPENPGP_SYMALGO_AES128		7
#define OPENPGP_SYMALGO_AES192		8
#define OPENPGP_SYMALGO_AES256		9
#define OPENPGP_SYMALGO_TWOFISH		10
#define OPENPGP_SYMALGO_CAMELLIA128	11	/* From GnuPG */
#define OPENPGP_SYMALGO_CAMELLIA192	12	/* From GnuPG */
#define OPENPGP_SYMALGO_CAMELLIA256	13	/* From GnuPG */

#define OPENPGP_HASH_MD5		1
#define OPENPGP_HASH_SHA1		2
#define OPENPGP_HASH_RIPEMD160		3
#define OPENPGP_HASH_SHA1X		4	/* In RFC2440, not in RFC4880 */
#define OPENPGP_HASH_MD2		5	/* In RFC2440, not in RFC4880 */
#define OPENPGP_HASH_TIGER192		6	/* In RFC2440, not in RFC4880 */
#define OPENPGP_HASH_HAVAL_5_160	7	/* In RFC2440, not in RFC4880 */
#define OPENPGP_HASH_SHA256		8
#define OPENPGP_HASH_SHA384		9
#define OPENPGP_HASH_SHA512		10
#define OPENPGP_HASH_SHA224		11

#define OPENPGP_COMP_NONE		0
#define OPENPGP_COMP_ZIP		1
#define OPENPGP_COMP_ZLIB		2
#define OPENPGP_COMP_BZIP2		3

#define OPENPGP_PACKET_PKSESSIONKEY	1
#define OPENPGP_PACKET_SIGNATURE	2
#define OPENPGP_PACKET_SYMSESSIONKEY	3
#define OPENPGP_PACKET_ONEPASSSIG	4
#define OPENPGP_PACKET_SECRETKEY	5
#define OPENPGP_PACKET_PUBLICKEY	6
#define OPENPGP_PACKET_SECRETSUBKEY	7
#define OPENPGP_PACKET_COMPRESSED	8
#define OPENPGP_PACKET_ENCRYPTED	9
#define OPENPGP_PACKET_MARKER		10
#define OPENPGP_PACKET_LITERALDATA	11
#define OPENPGP_PACKET_TRUST		12
#define OPENPGP_PACKET_UID		13
#define OPENPGP_PACKET_PUBLICSUBKEY	14
#define OPENPGP_PACKET_UAT		17
#define OPENPGP_PACKET_ENCRYPTED_MDC	18
#define OPENPGP_PACKET_MDC		19
#define OPENPGP_PACKET_COMMENT		61

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
#define OPENPGP_SIGSUB_REVOCABLE	7
#define OPENPGP_SIGSUB_CAPABILITIES	8	/* Legacy */
#define OPENPGP_SIGSUB_KEYEXPIRY	9
#define OPENPGP_SIGSUB_ARR		10	/* Placeholder in RFC */
#define OPENPGP_SIGSUB_PREFSYM		11
#define OPENPGP_SIGSUB_REVOCATION_KEY	12
#define OPENPGP_SIGSUB_ISSUER		16
#define OPENPGP_SIGSUB_ISSUER_UID	17	/* Legacy */
#define OPENPGP_SIGSUB_URL		18	/* Legacy */
#define OPENPGP_SIGSUB_ISSUER_FINGER	19	/* Legacy */
#define OPENPGP_SIGSUB_NOTATION		20
#define OPENPGP_SIGSUB_PREFHASH		21
#define OPENPGP_SIGSUB_PREFCOMPRESS	22
#define OPENPGP_SIGSUB_KEYSERVER	23
#define OPENPGP_SIGSUB_PREFKEYSERVER	24
#define OPENPGP_SIGSUB_PRIMARYUID	25
#define OPENPGP_SIGSUB_POLICYURI	26
#define OPENPGP_SIGSUB_KEYFLAGS		27
#define OPENPGP_SIGSUB_SIGNER_UID	28
#define OPENPGP_SIGSUB_REVOKE_REASON	29
#define OPENPGP_SIGSUB_FEATURES		30
#define OPENPGP_SIGSUB_SIGNATURE_TARGET	31
#define OPENPGP_SIGSUB_EMBEDDED_SIG	32

#endif /* __OPENPGP_H__ */

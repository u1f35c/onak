/**
 * @file armor.c
 * @brief Routines to (de)armor OpenPGP packet streams.
 *
 * Copyright 2002-2004, 2011 Jonathan McDowell <noodles@earth.li>
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

#include <stdlib.h>

#include "build-config.h"

#include "armor.h"
#include "keystructs.h"
#include "parsekey.h"

/**
 * @brief Line length we'll use for armored output
 */
#define ARMOR_WIDTH 64

/**
 * @brief CRC24 initialisation value
 */
#define CRC24_INIT 0xb704ceL
/**
 * @brief CRC24 polynomial value
 */
#define CRC24_POLY 0x1864cfbL

/**
 *
 */
static unsigned char encode64(unsigned char c) {
	if (c <= 25) {
		c += 'A';
	} else if (c >= 26 && c <= 51) {
		c += 'a' - 26;
	} else if (c >= 52 && c <= 61) {
		c += '0' - 52;
	} else if (c == 62) {
		c = '+';
	} else if (c == 63) {
		c = '/';
	} else {
		c = '?';
	}

	return c;
}

/**
 *
 */
static unsigned char decode64(unsigned char c) {
	if (c >= 'A' && c <= 'Z') {
		c -= 'A';
	} else if (c >= 'a' && c <= 'z') {
		c -= 'a' - 26;
	} else if (c >= '0' && c <= '9') {
		c -= '0' - 52;
	} else if (c == '+') {
		c = 62;
	} else if (c == '/') {
		c = 63;
	} else if (c == '=' || c == '-') {
		c = 64;
	} else {
		c = 65;
	}

	return c;
}

/**
 * @brief Holds the context of an ongoing ASCII armor operation
 */
struct armor_context {
	/** The last octet we got. */
	unsigned char lastoctet;
	/** The current octet we're expecting (0, 1 or 2). */
	int curoctet;
	/** The number of octets we've seen. */
	int count;
	/** A running CRC24 of the data we've seen. */
	long crc24;
	/** The function to output a character. */
	int (*putchar_func)(void *ctx, size_t count, void *c);
	/** Context for putchar_func. */
	void *ctx;
};

static void armor_init(struct armor_context *ctx)
{
	ctx->curoctet = 0;
	ctx->lastoctet = 0;
	ctx->count = 0;
	ctx->crc24 = CRC24_INIT;
}

static void armor_finish(struct armor_context *state)
{
	unsigned char c;

	switch (state->curoctet++) {
	case 0:
		break;
	case 1:
		c = encode64((state->lastoctet & 3) << 4);
		state->putchar_func(state->ctx, 1, &c);
		state->putchar_func(state->ctx, 1, (unsigned char *) "=");
		state->putchar_func(state->ctx, 1, (unsigned char *) "=");
		state->count += 3;
		if ((state->count % ARMOR_WIDTH) == 0) {
			state->putchar_func(state->ctx, 1,
				 (unsigned char *) "\n");
		}
		break;
	case 2:
		c = encode64((state->lastoctet & 0xF) << 2);
		state->putchar_func(state->ctx, 1, &c);
		state->putchar_func(state->ctx, 1, (unsigned char *) "=");
		state->count += 2;
		if ((state->count % ARMOR_WIDTH) == 0) {
			state->putchar_func(state->ctx, 1,
				 (unsigned char *) "\n");
		}
		break;
	}

	state->crc24 &= 0xffffffL;
	if ((state->count % ARMOR_WIDTH) != 0) {
		state->putchar_func(state->ctx, 1, (unsigned char *) "\n");
	}
	state->putchar_func(state->ctx, 1, (unsigned char *) "=");
	c = encode64(state->crc24 >> 18);
	state->putchar_func(state->ctx, 1, &c);
	c = encode64((state->crc24 >> 12) & 0x3F);
	state->putchar_func(state->ctx, 1, &c);
	c = encode64((state->crc24 >> 6) & 0x3F);
	state->putchar_func(state->ctx, 1, &c);
	c = encode64(state->crc24 & 0x3F);
	state->putchar_func(state->ctx, 1, &c);
	state->putchar_func(state->ctx, 1, (unsigned char *) "\n");

}


static int armor_putchar_int(void *ctx, unsigned char c)
{
	struct armor_context *state;
	unsigned char t;
	int i;

	state = (struct armor_context *) ctx;

	switch (state->curoctet++) {
	case 0:
		t = encode64(c >> 2);
		state->putchar_func(state->ctx, 1, &t);
		state->count++;
		break;
	case 1:
		t = encode64(((state->lastoctet & 3) << 4) + (c >> 4));
		state->putchar_func(state->ctx, 1, &t);
		state->count++;
		break;
	case 2:
		t = encode64(((state->lastoctet & 0xF) << 2) + (c >> 6));
		state->putchar_func(state->ctx, 1, &t);
		t = encode64(c & 0x3F);
		state->putchar_func(state->ctx, 1, &t);
		state->count += 2;
		break;
	}
	state->curoctet %= 3;
	state->lastoctet = c;
	
	state->crc24 ^= c << 16;
	for (i = 0; i < 8; i++) {
		state->crc24 <<= 1;
		if (state->crc24 & 0x1000000) {
			state->crc24 ^= CRC24_POLY;
		}
	}

	if ((state->count % ARMOR_WIDTH) == 0) {
		state->putchar_func(state->ctx, 1, (unsigned char *) "\n");
	}

	return 0;
}


static int armor_putchar(void *ctx, size_t count, void *c)
{
	int i;


	for (i = 0; i < count; i++) {
		armor_putchar_int(ctx, ((char *) c)[i]);
	}
	
	return 0;
}

/**
 * @brief Holds the context of an ongoing ASCII dearmor operation
 */
struct dearmor_context {
	/** The last octet we got. */
	unsigned char lastoctet;
	/** The current octet we're expecting (0, 1 or 2). */
	int curoctet;
	/** The number of octets we've seen. */
	int count;
	/** A running CRC24 of the data we've seen. */
	long crc24;
	/** The function to get the next character. */
	int (*getchar_func)(void *ctx, size_t count, void *c);
	/** Context for getchar_func. */
	void *ctx;
};

static void dearmor_init(struct dearmor_context *ctx)
{
	ctx->curoctet = 0;
	ctx->lastoctet = 0;
	ctx->count = 0;
	ctx->crc24 = CRC24_INIT;
}

static void dearmor_finish(struct dearmor_context *state)
{
	/*
	 * Check the checksum
	 */

	state->crc24 &= 0xffffffL;
	/*
	state->putchar_func(state->ctx, '\n');
	state->putchar_func(state->ctx, '=');
	state->putchar_func(state->ctx, encode64(state->crc24 >> 18));
	state->putchar_func(state->ctx, encode64((state->crc24 >> 12) & 0x3F));
	state->putchar_func(state->ctx, encode64((state->crc24 >> 6) & 0x3F));
	state->putchar_func(state->ctx, encode64(state->crc24 & 0x3F));
	*/
}


static int dearmor_getchar(void *ctx, unsigned char *c)
{
	struct dearmor_context *state;
	unsigned char tmpc;
	int i;

	state = (struct dearmor_context *) ctx;
	*c = 0;
	
	tmpc = 65;
	while (tmpc == 65) {
		state->getchar_func(state->ctx, 1, &tmpc);
		tmpc = decode64(tmpc);
	}

	if (tmpc != 64) {
		switch (state->curoctet++) {
		case 0:
			state->lastoctet = tmpc;
			tmpc = 65;
			while (tmpc == 65) {
				state->getchar_func(state->ctx, 1, &tmpc);
				tmpc = decode64(tmpc);
			}
			*c = (state->lastoctet << 2) + (tmpc >> 4);
			break;
		case 1:
			*c = ((state->lastoctet & 0xF) << 4) + (tmpc >> 2);
			break;
		case 2:
			*c = ((state->lastoctet & 3) << 6) + tmpc;
			break;
		}
	
		state->curoctet %= 3;
		state->lastoctet = tmpc;
		state->count++;
		
		state->crc24 ^= *c << 16;
		for (i = 0; i < 8; i++) {
			state->crc24 <<= 1;
			if (state->crc24 & 0x1000000) {
				state->crc24 ^= CRC24_POLY;
			}
		}
	}

	return (tmpc == 64);
}

static int dearmor_getchar_c(void *ctx, size_t count, void *c)
{
	int i, rc = 0;

	for (i = 0; i < count && rc == 0; i++) {
		rc = dearmor_getchar(ctx, &((unsigned char *) c)[i]);
	}

	return rc;
}

int armor_openpgp_stream(int (*putchar_func)(void *ctx, size_t count,
						void *c),
				void *ctx,
				struct openpgp_packet_list *packets)
{
	struct armor_context armor_ctx;

	/*
	 * Print armor header
	 */
	putchar_func(ctx, sizeof("-----BEGIN PGP PUBLIC KEY BLOCK-----\n") - 1,
		(unsigned char *) "-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
	putchar_func(ctx, sizeof("Version: onak " ONAK_VERSION "\n\n") - 1,
		(unsigned char *) "Version: onak " ONAK_VERSION "\n\n");
	
	armor_init(&armor_ctx);
	armor_ctx.putchar_func = putchar_func;
	armor_ctx.ctx = ctx;
	write_openpgp_stream(armor_putchar, &armor_ctx, packets);
	armor_finish(&armor_ctx);

	/*
	 * Print armor footer
	 */
	putchar_func(ctx, sizeof("-----END PGP PUBLIC KEY BLOCK-----\n") - 1,
		(unsigned char *) "-----END PGP PUBLIC KEY BLOCK-----\n");

	return 0;
}

int dearmor_openpgp_stream(int (*getchar_func)(void *ctx, size_t count,
						void *c),
				void *ctx,
				struct openpgp_packet_list **packets)
{
	struct dearmor_context dearmor_ctx;
	unsigned char curchar;
	int state = 0;
	int count = 0;

	/*
	 * Look for armor header. We want "-----BEGIN.*\n", then some headers
	 * with :s in them, then a blank line, then the data.
	 */
	state = 1;
	while (state != 4 && !getchar_func(ctx, 1, &curchar)) {
		switch (state) {
			case 0:
				if (curchar == '\n') {
					count = 0;
					state = 1;
				}
				break;
			case 1:
				if (curchar == '-') {
					count++;
					if (count == 5) {
						state = 2;
					}
				} else if (curchar != '\n') {
					state = 0;
				}
				break;
			case 2:
				if (curchar == 'B') {
					count = 0;
					state = 3;
				} else {
					state = 0;
				}
				break;
			case 3:
				if (curchar == '\n') {
					count++;
					if (count == 2) {
						state = 4;
					}
				} else if (curchar != '\r') {
					count = 0;
				}
				break;
		}
	}

	if (state == 4) {
		dearmor_init(&dearmor_ctx);
		dearmor_ctx.getchar_func = getchar_func;
		dearmor_ctx.ctx = ctx;
		read_openpgp_stream(dearmor_getchar_c, &dearmor_ctx,
			packets, 0);
		dearmor_finish(&dearmor_ctx);
		/*
		 * TODO: Look for armor footer
		 */
	}

	return 0;
}

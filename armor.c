/*
 * armor.c - Routines to (de)armor OpenPGP packet streams.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: armor.c,v 1.7 2003/09/30 20:40:10 noodles Exp $
 */

#include <assert.h>
#include <stdlib.h>

#include "armor.h"
#include "keystructs.h"
#include "onak-conf.h"
#include "parsekey.h"

#define ARMOR_WIDTH 64

#define CRC24_INIT 0xb704ceL
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
		assert(c < 64);
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
 *	@lastoctet: The last octet we got.
 *	@curoctet: The current octet we're expecting (0, 1 or 2).
 *	@count: The number of octets we've seen.
 *	@crc24: A running CRC24 of the data we've seen.
 *	@putchar_func: The function to output a character.
 *	@ctx: Context for putchar_func.
 */
struct armor_context {
	unsigned char lastoctet;
	int curoctet;
	int count;
	long crc24;
	int (*putchar_func)(void *ctx, size_t count, unsigned char *c);
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
		break;
	case 2:
		c = encode64((state->lastoctet & 0xF) << 2);
		state->putchar_func(state->ctx, 1, &c);
		state->putchar_func(state->ctx, 1, (unsigned char *) "=");
		break;
	}

	state->crc24 &= 0xffffffL;
	state->putchar_func(state->ctx, 1, (unsigned char *) "\n");
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

	assert(ctx != NULL);
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


static int armor_putchar(void *ctx, size_t count, unsigned char *c)
{
	int i;

	for (i = 0; i < count; i++) {
		armor_putchar_int(ctx, c[i]);
	}
	
	return 0;
}

/**
 *	@lastoctet: The last octet we got.
 *	@curoctet: The current octet we're expecting (0, 1 or 2).
 *	@count: The number of octets we've seen.
 *	@crc24: A running CRC24 of the data we've seen.
 *	@putchar_func: The function to output a character.
 *	@ctx: Context for putchar_func.
 */
struct dearmor_context {
	unsigned char lastoctet;
	int curoctet;
	int count;
	long crc24;
	int (*getchar_func)(void *ctx, size_t count, unsigned char *c);
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

	assert(ctx != NULL);
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

static int dearmor_getchar_c(void *ctx, size_t count, unsigned char *c)
{
	int i, rc = 0;

	for (i = 0; i < count && rc == 0; i++) {
		rc = dearmor_getchar(ctx, &c[i]);
	}

	return rc;
}

/**
 *	armor_openpgp_stream - Takes a list of OpenPGP packets and armors it.
 *	@putchar_func: The function to output the next armor character.
 *	@ctx: The context pointer for putchar_func.
 *	@packets: The list of packets to output.
 *
 *	This function ASCII armors a list of OpenPGP packets and outputs it
 *	using putchar_func.
 */
int armor_openpgp_stream(int (*putchar_func)(void *ctx, size_t count,
						unsigned char *c),
				void *ctx,
				struct openpgp_packet_list *packets)
{
	struct armor_context armor_ctx;

	/*
	 * Print armor header
	 */
	putchar_func(ctx, sizeof("-----BEGIN PGP PUBLIC KEY BLOCK-----\n") - 1,
		(unsigned char *) "-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
	putchar_func(ctx, sizeof("Version: onak " VERSION "\n\n") - 1,
		(unsigned char *) "Version: onak " VERSION "\n\n");
	
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

/**
 *	dearmor_openpgp_stream - Reads & decodes an ACSII armored OpenPGP msg.
 *	@getchar_func: The function to get the next character from the stream.
 *	@ctx: The context pointer for getchar_func.
 *	@packets: The list of packets.
 *
 *	This function uses getchar_func to read characters from an ASCII
 *	armored OpenPGP stream and outputs the data as a linked list of
 *	packets.
 */
int dearmor_openpgp_stream(int (*getchar_func)(void *ctx, size_t count,
						unsigned char *c),
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

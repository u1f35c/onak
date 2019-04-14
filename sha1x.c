/*
 * sha1x.c - Double width SHA-1 as per PGP 5.5
 *
 * Copyright 2013 Jonathan McDowell <noodles@earth.li>
 *
 * This is based on the description / code from PGP 5.5, where it is called
 * "SHA Double". I have seen reference to SHA1X elsewhere, which is a more
 * concise name, so I have used that here.
 *
 * I can't imagine there is a good reason to use this code other than for
 * verifying signatures on ancient PGP keys.
 *
 * Placed into the public domain.
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "build-config.h"

#ifdef HAVE_NETTLE
#include <nettle/sha.h>
#else
#include "sha1.h"
#endif
#include "sha1x.h"

#define BUFSIZE 64

void sha1x_init(struct sha1x_ctx *ctx)
{
	unsigned char zeros[3];

	zeros[0] = zeros[1] = zeros[2] = 0;
	sha1_init(&ctx->a);
	sha1_init(&ctx->b);
	sha1_init(&ctx->c);
	sha1_init(&ctx->d);

	sha1_update(&ctx->b, 1, zeros);
	sha1_update(&ctx->c, 2, zeros);
	sha1_update(&ctx->d, 3, zeros);

	/* We start at 0, so even */
	ctx->odd = false;
}

void sha1x_update(struct sha1x_ctx *ctx, unsigned length, const uint8_t *data)
{
	uint8_t evenbuf[BUFSIZE], *evenp;
	uint8_t oddbuf[BUFSIZE], *oddp;
	bool newodd;

	oddp = oddbuf;
	evenp = evenbuf;

	/* Track whether our first byte next time round is even or odd */
	newodd = ctx->odd ^ (length & 1);

	/* If our first byte is odd this time, add it to the odd buffer */
	if (ctx->odd && length != 0) {
		*oddp++ = *data++;
		length--;
	}
	ctx->odd = newodd;

	while (length != 0) {
		while (length != 0 && oddp < oddbuf + BUFSIZE) {
			*evenp++ = *data++;
			length--;
			if (length == 0) {
				break;
			}
			*oddp++ = *data++;
			length--;
		}
		sha1_update(&ctx->a, evenp - evenbuf, evenbuf);
		sha1_update(&ctx->b, evenp - evenbuf, evenbuf);
		sha1_update(&ctx->c, oddp - oddbuf, oddbuf);
		sha1_update(&ctx->d, oddp - oddbuf, oddbuf);

		oddp = oddbuf;
		evenp = evenbuf;
	}
}

void sha1x_digest(struct sha1x_ctx *ctx, unsigned length, uint8_t *digest)
{
	uint8_t sha1final[8][SHA1_DIGEST_SIZE];
	uint8_t zeros[7];
	struct sha1_ctx e, f, g, h;
	int i;

	sha1_digest(&ctx->a, SHA1_DIGEST_SIZE, sha1final[0]);
	sha1_digest(&ctx->b, SHA1_DIGEST_SIZE, sha1final[1]);
	sha1_digest(&ctx->c, SHA1_DIGEST_SIZE, sha1final[2]);
	sha1_digest(&ctx->d, SHA1_DIGEST_SIZE, sha1final[3]);

	/* XOR sha1-c into sha1-a & sha1-d into sha1-b */
	for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
		sha1final[0][i] ^= sha1final[2][i];
		sha1final[1][i] ^= sha1final[3][i];
	}

	sha1_init(&e);
	sha1_init(&f);
	sha1_init(&g);
	sha1_init(&h);

	memset(zeros, 0, sizeof(zeros));
	sha1_update(&e, 4, zeros);
	sha1_update(&f, 5, zeros);
	sha1_update(&g, 6, zeros);
	sha1_update(&h, 7, zeros);

	sha1_update(&e, SHA1_DIGEST_SIZE, sha1final[0]);
	sha1_update(&f, SHA1_DIGEST_SIZE, sha1final[0]);
	sha1_update(&g, SHA1_DIGEST_SIZE, sha1final[1]);
	sha1_update(&h, SHA1_DIGEST_SIZE, sha1final[1]);

	sha1_digest(&e, SHA1_DIGEST_SIZE, sha1final[4]);
	sha1_digest(&f, SHA1_DIGEST_SIZE, sha1final[5]);
	sha1_digest(&g, SHA1_DIGEST_SIZE, sha1final[6]);
	sha1_digest(&h, SHA1_DIGEST_SIZE, sha1final[7]);

	/* XOR sha1-g into sha1-e & sha1-h into sha1-f */
	for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
		sha1final[4][i] ^= sha1final[6][i];
		sha1final[5][i] ^= sha1final[7][i];
	}

	if (length > SHA1X_DIGEST_SIZE) {
		length = SHA1X_DIGEST_SIZE;
	}

	for (i = 0; i < length; i++) {
		if (i < SHA1_DIGEST_SIZE) {
			digest[i] = sha1final[4][i];
		} else {
			digest[i] = sha1final[6][i - SHA1_DIGEST_SIZE];
		}
	}
}

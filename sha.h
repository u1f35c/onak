#ifndef __SHA_H__
#define __SHA_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
// #include <stdint.h>
#include <inttypes.h>

#include "bithelp.h"

typedef struct {
    uint32_t	h0,h1,h2,h3,h4;
    uint32_t	nblocks;
    uint8_t	buf[64];
    int		count;
} SHA1_CONTEXT;

void sha1_init(SHA1_CONTEXT *);
void sha1_write(SHA1_CONTEXT *, uint8_t *, size_t);
void sha1_final(SHA1_CONTEXT *);
unsigned char *sha1_read(SHA1_CONTEXT *);

#endif /* __SHA_H__ */

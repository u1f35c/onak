/*
 SHA-1 in C

 By Steve Reid <steve@edmweb.com>, with small changes to make it
 fit into mutt by Thomas Roessler <roessler@does-not-exist.org>.

*/

#ifndef _SHA1_H
# define _SHA1_H

#include <stdint.h>
#include <sys/types.h>

struct sha1_ctx {
  uint32_t state[5];
  uint32_t count[2];
  unsigned char buffer[64];
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, unsigned length, const uint8_t *data);
void sha1_digest(struct sha1_ctx *ctx, unsigned length, uint8_t *digest);

# define SHA1_Transform SHA1Transform
# define SHA1_Init SHA1Init
# define SHA1_Update SHA1Update
# define SHA1_Final SHA1Final

# define SHA1_DIGEST_SIZE 20

#endif


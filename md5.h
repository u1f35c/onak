#ifndef __MD5_H__
#define __MD5_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bithelp.h"

typedef struct {
    unsigned int  A,B,C,D;	  /* chaining variables */
    unsigned int  nblocks;
    unsigned char buf[64];
    int  count;
} MD5_CONTEXT;

void md5_init(MD5_CONTEXT *);
void md5_write(MD5_CONTEXT *, unsigned char *, size_t);
void md5_final(MD5_CONTEXT *);
unsigned char *md5_read(MD5_CONTEXT *);

#endif /* __MD5_H__ */

/* Declaration of functions and data types used for MD5 sum computing
   library functions.
   Copyright (C) 1995,1996,1997,1999,2000,2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _MD5_H
#define _MD5_H 1

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
typedef size_t md5_uintptr;

/* Structure to save state of computation between the single steps.  */
struct md5_ctx
{
  char buffer[128];
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;

  uint32_t total[2];
  uint32_t buflen;
};

/*
 * The following three functions are build up the low level used in
 * the functions `md5_stream' and `md5_buffer'.
 */

/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
extern void md5_init(struct md5_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
extern void md5_update(struct md5_ctx *ctx, unsigned length,
		const uint8_t *buffer);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 16 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
extern void md5_digest(struct md5_ctx *ctx, unsigned length, uint8_t *resbuf);

#endif /* md5.h */

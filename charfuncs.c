/*
 * charfuncs.c - Routines for dealing with character streams.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "charfuncs.h"

/**
 *	buffer_fetchchar - Fetches a char from a buffer.
 *	@ctx: Our buffer context structure.
 *	@count: The number of characters to get from the buffer.
 *	@c: Where to put the characters retrieved.
 */
int buffer_fetchchar(void *ctx, size_t count, unsigned char *c)
{
	struct buffer_ctx *buf = NULL;
	int i;
	
	buf = (struct buffer_ctx *) ctx;
	for (i = 0; i < count; i++) {
		c[i] = buf->buffer[buf->offset++];
	}

	return (((buf->offset) == (buf->size)) ? 1 : 0);
}

/**
 *	buffer_putchar - Puts a char to a buffer.
 *	@ctx: Our buffer context structure.
 *	@count: The number of characters to put into the buffer.
 *	@c: The characters to add to the buffer.
 *
 *	Adds characters to the buffer references by the buffer context. If we
 *	fill it then we double the size of the current buffer and then add the
 *	rest.
 */
int buffer_putchar(void *ctx, size_t count, unsigned char *c)
{
	struct buffer_ctx *buf = NULL;
	size_t newsize = 0;
	int i;
	
	buf = (struct buffer_ctx *) ctx;

	for (newsize = buf->size; newsize < (buf->offset + count);
			newsize *= 2) ;

	if (newsize != buf->size) {
		buf->buffer = realloc(buf->buffer, newsize);
		buf->size = newsize;
	}
	
	for (i = 0; i < count; i++) {
		buf->buffer[buf->offset++] = c[i];
	}

	return 1;
}

/**
 *	file_fetchchar - Fetches a char from a file.
 */
int file_fetchchar(void *fd, size_t count, unsigned char *c)
{
	return !(read( *(int *) fd, c, count));
}

/**
 *	file_putchar - Puts a char to a file.
 */
int file_putchar(void *fd, size_t count, unsigned char *c)
{
	return !(write( *(int *) fd, c, count));
}

/*
 * charfuncs.h - Routines for dealing with character streams.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: charfuncs.h,v 1.4 2003/10/04 10:21:40 noodles Exp $
 */

#ifndef __CHARFUNCS_H__
#define __CHARFUNCS_H__

#include <stdlib.h>

/**
 *	buffer_ctx - Shared with CGI buffer stuff...
 *	@buffer: The data buffer.
 *	@offset: Our current position in the buffer.
 *	@size: The size of the data buffer.
 */
struct buffer_ctx {
	char *buffer;
	size_t offset;
	size_t size;
};

/**
 *	buffer_fetchchar - Fetches a char from a buffer.
 *	@ctx: Our buffer context structure.
 *	@count: The number of characters to get from the buffer.
 *	@c: Where to put the characters retrieved.
 */
int buffer_fetchchar(void *ctx, size_t count, unsigned char *c);

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
int buffer_putchar(void *ctx, size_t count, unsigned char *c);

/**
 *	file_fetchchar - Fetches a char from a file.
 */
int file_fetchchar(void *fd, size_t count, unsigned char *c);

/**
 *	file_putchar - Puts a char to a file.
 */
int file_putchar(void *fd, size_t count, unsigned char *c);

/**
 *	stdin_getchar - Gets a char from stdin.
 */
int stdin_getchar(void *ctx, size_t count, unsigned char *c);

/**
 *	stdout_putchar - Puts a char to stdout.
 */
int stdout_putchar(void *ctx, size_t count, unsigned char *c);

#endif /* __CHARFUNCS_H__ */

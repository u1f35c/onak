/*
 * charfuncs.c - Routines for dealing with character streams.
 *
 * Copyright 2002 Jonathan McDowell <noodles@earth.li>
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "charfuncs.h"

/*
 * Fetches a char from a buffer.
 *	@ctx: Our buffer context structure.
 *	@count: The number of characters to get from the buffer.
 *	@c: Where to put the characters retrieved.
 */
int buffer_fetchchar(void *ctx, size_t count, void *c)
{
	struct buffer_ctx *buf = NULL;
	
	buf = (struct buffer_ctx *) ctx;

	if (buf->offset + count > buf->size) {
		return 1;
	}
	
	memcpy(c, &buf->buffer[buf->offset], count);
	buf->offset += count;

	return 0;
}

/*
 *	buffer_putchar - Puts a char to a buffer.
 *	@ctx: Our buffer context structure.
 *	@count: The number of characters to put into the buffer.
 *	@c: The characters to add to the buffer.
 *
 *	Adds characters to the buffer references by the buffer context. If we
 *	fill it then we double the size of the current buffer and then add the
 *	rest.
 */
int buffer_putchar(void *ctx, size_t count, void *c)
{
	struct buffer_ctx *buf = NULL;
	size_t newsize = 0;
	
	buf = (struct buffer_ctx *) ctx;

	for (newsize = buf->size; newsize < (buf->offset + count);
			newsize *= 2) ;

	if (newsize != buf->size) {
		buf->buffer = realloc(buf->buffer, newsize);
		buf->size = newsize;
	}

	memcpy(&buf->buffer[buf->offset], c, count);
	buf->offset += count;
	
	return 1;
}

/*
 * Fetches a char from a file.
 */
int file_fetchchar(void *fd, size_t count, void *c)
{
	return !(read( *(int *) fd, c, count));
}

/*
 * Puts a char to a file.
 */
int file_putchar(void *fd, size_t count, void *c)
{
	return !(write( *(int *) fd, c, count));
}

/*
 * Gets a char from stdin.
 */
int stdin_getchar(void *ctx, size_t count, void *c)
{
	return (fread(c, 1, count, stdin) != count);
}

/*
 * Puts a char to stdout.
 */
int stdout_putchar(void *ctx, size_t count, void *c)
{
	return (fwrite(c, 1, count, stdout) != count);
}

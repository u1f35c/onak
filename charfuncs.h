/*
 * charfuncs.h - Routines for dealing with character streams.
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
int buffer_fetchchar(void *ctx, size_t count, void *c);

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
int buffer_putchar(void *ctx, size_t count, void *c);

/**
 *	file_fetchchar - Fetches a char from a file.
 */
int file_fetchchar(void *fd, size_t count, void *c);

/**
 *	file_putchar - Puts a char to a file.
 */
int file_putchar(void *fd, size_t count, void *c);

/**
 *	stdin_getchar - Gets a char from stdin.
 */
int stdin_getchar(void *ctx, size_t count, void *c);

/**
 *	stdout_putchar - Puts a char to stdout.
 */
int stdout_putchar(void *ctx, size_t count, void *c);

#endif /* __CHARFUNCS_H__ */
